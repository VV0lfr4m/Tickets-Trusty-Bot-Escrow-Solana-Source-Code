use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
    program_error::ProgramError,
    msg,
    program::invoke_signed,
    system_instruction,
    sysvar::{clock::Clock, Sysvar},
    rent::Rent,
    program_pack::{IsInitialized, Pack, Sealed},
};
use solana_program::system_program;
use solana_program::pubkey;
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::declare_id;
use solana_security_txt::security_txt;

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "Tickets Trusty Bot Escrow",
    project_url: "https://github.com/VV0lfr4m/Tickets-Trusty-Bot-Escrow-Solana-Source-Code",
    contacts: "email:vladlen.tsykin@gmail.com",
    source_code: "https://github.com/VV0lfr4m/Tickets-Trusty-Bot-Escrow-Solana-Source-Code"
}

declare_id!("GK37MNRqnsVpPjq2T28BZecnuDuKtQeLFVnd54BNdPu8");
pub const AUTHORITY_PUBKEY: Pubkey = pubkey!("EcT7YCrKbGroidXgeQaPYUkrdyqdhYa6kvdr1DSLiFpp");
pub const DEFAULT_AUTORELEASE_SECS: u64 = 12*60*60; // 12 hours
/// Escrow status
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Debug)]
#[borsh(use_discriminant = true)]
pub enum EscrowStatus {
    Pending = 0,
    Paid = 1,
    Released = 2,
    Refunded = 3,
    AutoReleased = 4,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct EscrowData {
    pub is_initialized: bool,
    pub trade_id12: [u8; 12],
    pub seller: Pubkey,
    pub buyer: Pubkey,
    pub amount: u64,
    pub status: u8,
    pub created_at: i64,
    pub paid_at: i64,
    pub qr_hash: [u8; 32],
}

impl EscrowData {
    pub const LEN: usize = 1 + 12 + 32 + 32 + 8 + 1 + 8 + 8 + 32;
}
const FIXED_BENEFICIARY: Pubkey = pubkey!("FqYf67MfsD9pQtRWnfpJxQQP13xCnowiWhLNoCfHun76");

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = instruction_data[0];

    match instruction {
        0 => create_escrow(program_id, accounts, &instruction_data[1..]),
        1 => pay_escrow(program_id, accounts),
        2 => release_escrow(program_id, accounts),
        3 => refund_escrow(program_id, accounts),
        4 => auto_release_escrow(program_id, accounts, &instruction_data[1..]),
        5 => close_escrow(program_id, accounts),
        6 => close_vault(program_id, accounts),
        7 => set_buyer_wallet(program_id, accounts, &instruction_data[1..]),
        8 => mark_paid(program_id, accounts),
        #[cfg(feature = "test")]
                250 => {
                    return process_test_patch_created_at(program_id, accounts, instruction_data);
                }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn try_optional_close_after_terminal<'info>(
    program_id: &Pubkey,
    escrow_acc: AccountInfo<'info>,
    vault_acc: AccountInfo<'info>,
    sysprog: AccountInfo<'info>,
    beneficiary: AccountInfo<'info>,
    escrow_data: &mut EscrowData,
    close_escrow_flag: bool,
) -> ProgramResult {
    use solana_program::{program::invoke_signed, system_instruction, system_program};

    // --- basic guards (non-fatal -> skip) ---
    if sysprog.key != &system_program::ID {
        msg!("closing: skipped — invalid system_program");
        return Ok(());
    }
    if beneficiary.key != &FIXED_BENEFICIARY {
        msg!("closing: skipped — beneficiary != FIXED_BENEFICIARY");
        return Ok(());
    }

    // --- 1) drain vault -> beneficiary (treasury) ---
    let (derived_vault, bump) = Pubkey::find_program_address(
        &[b"vault".as_ref(), &escrow_data.trade_id12],
        program_id,
    );
    if &derived_vault != vault_acc.key {
        msg!("closing: vault seeds mismatch -> skip drain");
    } else {
        let lamports = **vault_acc.lamports.borrow();
        if lamports > 0 {
            let signer_seeds: &[&[u8]] =
                &[b"vault".as_ref(), &escrow_data.trade_id12, &[bump]];
            invoke_signed(
                &system_instruction::transfer(vault_acc.key, beneficiary.key, lamports),
                &[vault_acc.clone(), beneficiary.clone(), sysprog.clone()],
                &[signer_seeds],
            )?;
            msg!("closing: drained {} lamports from vault to treasury", lamports);
        } else {
            msg!("closing: vault already empty");
        }
    }

    // --- 2) optionally free escrow account (rent) ---
    if !close_escrow_flag {
        msg!("closing: escrow skip (flag=false) — keep for audit");
        return Ok(());
    }
    if escrow_acc.owner != program_id {
        msg!("closing: escrow owner mismatch -> skip");
        return Ok(());
    }

    if escrow_data.is_initialized {
        let escrow_balance = **escrow_acc.lamports.borrow();
        if escrow_balance > 0 {
            **beneficiary.lamports.borrow_mut() = beneficiary
                .lamports()
                .checked_add(escrow_balance)
                .ok_or(ProgramError::Custom(0xdead))?;
            **escrow_acc.lamports.borrow_mut() = 0;
            msg!("closing: escrow rent transferred to treasury");
        } else {
            msg!("closing: escrow balance already zero");
        }

        // deinit & free data; serialization is optional for your policy
        escrow_data.is_initialized = false;
        // escrow_data.serialize(&mut &mut escrow_acc.data.borrow_mut()[..])?;
        let _ = escrow_acc.realloc(0, false);
        msg!("closing: escrow data freed (realloc(0))");
    } else {
        msg!("closing: escrow already deinitialized");
    }

    Ok(())
}

/// === 0. CREATE_ESCROW ===
fn create_escrow(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    // [0] escrow_account (PDA, writable, uninit, owned by program)
    // [1] vault_pda     (PDA, writable, uninit, system owner)
    // [2] seller        (readonly)            // ОТРИМУВАЧ, НЕ signer
    // [3] authority     (signer, payer)       // БОТ

    // === 1. Розпаковуємо акаунти ===
    let account_info_iter = &mut accounts.iter();
        let escrow_acc     = next_account_info(account_info_iter)?; // [0]
        let vault_acc      = next_account_info(account_info_iter)?; // [1]
        let seller_acc     = next_account_info(account_info_iter)?; // [2]  <-- ДОДАНО
        let authority_acc  = next_account_info(account_info_iter)?; // [3]  <-- ДОДАНО
        let system_program = next_account_info(account_info_iter)?; // [4]

    if !authority_acc.is_signer {
            msg!("Missing required signature: authority");
            return Err(ProgramError::MissingRequiredSignature);
        }
    if escrow_acc.owner != program_id && escrow_acc.lamports() > 0 {
            msg!("escrow_acc not owned by this program");
            return Err(ProgramError::IncorrectProgramId);
        }
    if *system_program.key != solana_program::system_program::id() {
            msg!("system_program key mismatch");
            return Err(ProgramError::IncorrectProgramId);
        }
    // === 2. Десеріалізація аргументів ===
    if data.len() < 12 + 8 + 32 {
        msg!("invalid create_escrow data len: {}", data.len());
        return Err(ProgramError::InvalidInstructionData);
    }

    let (trade_id12_raw, rest) = data.split_at(12);
    let mut trade_id12 = [0u8; 12];
    trade_id12.copy_from_slice(trade_id12_raw);

    let buyer = Pubkey::default();

    let (amount_bytes, rest) = rest.split_at(8);
    let amount = u64::from_le_bytes(amount_bytes.try_into().unwrap());

    let qr_hash: [u8; 32] = rest[..32].try_into().unwrap();

    // === 3. Підготовка seeds/bump для PDA ===
    let escrow_seeds: &[&[u8]] = &[b"escrow".as_ref(), &trade_id12[..]];
    let (escrow_pda, bump) = Pubkey::find_program_address(escrow_seeds, program_id);
    let signer_seeds: &[&[u8]] = &[b"escrow".as_ref(), &trade_id12[..], &[bump]];
    // === 3b. Seeds/bump для vault_pda (НОВЕ) ===
    let vault_seeds: &[&[u8]] = &[b"vault".as_ref(), &trade_id12[..]];
    let (vault_pda, vault_bump) = Pubkey::find_program_address(vault_seeds, program_id);
    let vault_signer_seeds: &[&[u8]] = &[b"vault".as_ref(), &trade_id12[..], &[vault_bump]];


    if escrow_acc.key != &escrow_pda {
            msg!("escrow_pda mismatch");
            return Err(ProgramError::InvalidSeeds);
    }
    if vault_acc.key  != &vault_pda {
            msg!("vault_pda mismatch");
            return Err(ProgramError::InvalidSeeds);
    }

    if escrow_acc.lamports() > 0 {
                // акаунт нашої програми?
                if escrow_acc.owner != program_id {
                    msg!("escrow_acc not owned by this program");
                    return Err(ProgramError::IncorrectProgramId);
                }
                // розмір очікуваний?
                if escrow_acc.data_len() != EscrowData::LEN {
                    msg!("escrow_acc wrong size: got {}, need {}", escrow_acc.data_len(), EscrowData::LEN);
                    return Err(ProgramError::InvalidAccountData);
                }
                // спроба десеріалізації і перевірка прапора
                let existing = EscrowData::try_from_slice(&escrow_acc.data.borrow())?;
                if existing.is_initialized {
                    msg!("Escrow already initialized for this trade_id={:?}", existing.trade_id12);
                    return Err(ProgramError::AccountAlreadyInitialized);
                }
            }
    // === 4. Якщо акаунт не існує — створюємо через CPI (invoke_signed) ===
    if escrow_acc.lamports() == 0 {
        let rent = Rent::get()?;
        let rent_lamports = rent.minimum_balance(EscrowData::LEN);

        let create_acc_ix = system_instruction::create_account(
            authority_acc.key,             // payer = authority
                        escrow_acc.key,                // new account = PDA
                        rent_lamports,
                        EscrowData::LEN as u64,
                        program_id,
        );
        invoke_signed(
            &create_acc_ix,
            &[authority_acc.clone(), escrow_acc.clone(), system_program.clone()],
            &[signer_seeds],
        )?;
    }


    // === 4b. Створюємо vault_pda (space=0, owner=System, лампортів мінімум) ===

        if vault_acc.lamports() == 0 {
            let rent = Rent::get()?;
            let lamports = rent.minimum_balance(0); // ~890_880 лампортів на сьогодні
            let ix = system_instruction::create_account(
                authority_acc.key,                  // платник
                vault_acc.key,                 // новий акаунт (PDA)
                lamports,                      // !!! НЕ 1 лампорт
                0,                             // space = 0
                &solana_program::system_program::ID, // owner = System Program
            );
            invoke_signed(
                &ix,
                &[authority_acc.clone(), vault_acc.clone(), system_program.clone()],
                &[vault_signer_seeds], // підпис для PDA
            )?;
        }

    // === 6. Ініціалізація escrow data ===
    let mut escrow_data = EscrowData {
        is_initialized: true,
        trade_id12,
        seller: *seller_acc.key,
        buyer,
        amount,
        status: EscrowStatus::Pending as u8,
        created_at: Clock::get()?.unix_timestamp,
        paid_at: 0,
        qr_hash,
        // authority: *authority_acc.key,          // (рекомендовано додати у структуру і перевіряти надалі)
    };
    escrow_data.serialize(&mut &mut escrow_acc.data.borrow_mut()[..])?;
    msg!("Escrow Created: {:?}", escrow_data);
    Ok(())
}

/// === 1. PAY_ESCROW ===
fn pay_escrow(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    // [0] escrow_pda (read/write), [1] vault_pda (writable, System owner),
    // [2] payer (signer), [3] system_program
    let account_info_iter = &mut accounts.iter();
    let escrow_acc     = next_account_info(account_info_iter)?; // [0]
    let vault_acc      = next_account_info(account_info_iter)?; // [1]
    let payer_acc      = next_account_info(account_info_iter)?; // [2] <-- це наш buyer-кандидат
    let system_program = next_account_info(account_info_iter)?; // [3]

    // --- перевірки власників/ідентичностей ---
    if escrow_acc.owner != program_id {
        msg!("escrow_acc not owned by this program");
        return Err(ProgramError::IncorrectProgramId);
    }
    if *system_program.key != solana_program::system_program::ID {
        msg!("wrong system_program");
        return Err(ProgramError::IncorrectProgramId);
    }

    // --- десеріалізація state ---
    let mut escrow_data = EscrowData::try_from_slice(&escrow_acc.data.borrow())?;
    if escrow_data.status != EscrowStatus::Pending as u8 {
        msg!("Status is not Pending");
        return Err(ProgramError::InvalidAccountData);
    }

    // --- валідація PDA за сид-схемою ---
    let (expected_escrow, _) =
        Pubkey::find_program_address(&[b"escrow".as_ref(), &escrow_data.trade_id12[..]], program_id);
    if escrow_acc.key != &expected_escrow {
        msg!("escrow_pda mismatch");
        return Err(ProgramError::InvalidSeeds);
    }
    let (expected_vault, _) =
        Pubkey::find_program_address(&[b"vault".as_ref(),  &escrow_data.trade_id12[..]], program_id);
    if vault_acc.key != &expected_vault {
        msg!("vault_pda mismatch");
        return Err(ProgramError::InvalidSeeds);
    }

    // --- перший депозит фіксує buyer ---
    if escrow_data.buyer == Pubkey::default() {
        if !payer_acc.is_signer {
            msg!("buyer must sign the first deposit");
            return Err(ProgramError::MissingRequiredSignature);
        }
        escrow_data.buyer = *payer_acc.key;
    } else if escrow_data.buyer != *payer_acc.key {
        msg!("buyer mismatch");
        return Err(ProgramError::IllegalOwner);
    }

    // --- переказ очікуваної суми на vault_pda ---
    let amount = escrow_data.amount; // номінал, закладений у create_escrow
    solana_program::program::invoke(
        &solana_program::system_instruction::transfer(payer_acc.key, vault_acc.key, amount),
        &[payer_acc.clone(), vault_acc.clone(), system_program.clone()],
    )?;

    if escrow_data.paid_at == 0 {
        escrow_data.paid_at = Clock::get()?.unix_timestamp;
    }

    // --- оновлення статусу ---
    escrow_data.status = EscrowStatus::Paid as u8;
    escrow_data.serialize(&mut &mut escrow_acc.data.borrow_mut()[..])?;
    msg!("Escrow Paid: trade_id={:?}", escrow_data.trade_id12);
    Ok(())
}

/// === 2. RELEASE_ESCROW ===
pub fn release_escrow(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    // Accounts:
    // [0] escrow_pda   (writable, owned by this program)
    // [1] vault_pda    (writable, owned by System Program)
    // [2] seller       (writable)    -- одержувач
    // [3] authority    (signer)      -- модератор/бот
    // [4] system_program

    let [escrow_acc,
             vault_acc,
             seller_acc,
             authority_acc,
             system_program_acc,
             benef_acc,
             ..] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

    // --- базові перевірки
    if escrow_acc.owner != program_id {
        msg!("escrow_acc not owned by program");
        return Err(ProgramError::IncorrectProgramId);
    }
    if !authority_acc.is_signer {
        msg!("Missing required signature: authority");
        return Err(ProgramError::MissingRequiredSignature);
    }
    if *system_program_acc.key != system_program::id() {
        msg!("system_program key mismatch");
        return Err(ProgramError::IncorrectProgramId);
    }
    if vault_acc.owner != system_program_acc.key {
        msg!("vault_pda must be system-owned");
        return Err(ProgramError::IncorrectProgramId);
    }
    // (не обов’язково, але дає зрозумілі помилки, якщо мета-флаги зібрані криво)
    if !escrow_acc.is_writable || !vault_acc.is_writable || !seller_acc.is_writable {
        msg!("writability mismatch for escrow/vault/seller");
        return Err(ProgramError::InvalidAccountData);
    }

    // --- читаємо state
    let mut escrow_data = EscrowData::try_from_slice(&escrow_acc.data.borrow())?;
    if !escrow_data.is_initialized {
        msg!("escrow not initialized");
        return Err(ProgramError::UninitializedAccount);
    }
    if escrow_data.status != EscrowStatus::Paid as u8 {
        msg!("status must be Paid");
        return Err(ProgramError::InvalidAccountData);
    }
    if *seller_acc.key != escrow_data.seller {
        msg!("Unauthorized: seller_acc.key != escrow_data.seller");
        return Err(ProgramError::IllegalOwner);
    }
    if escrow_data.amount == 0 {
        msg!("nothing to release");
        return Err(ProgramError::InsufficientFunds);
    }

    // --- перевіряємо та відновлюємо PDA для vault (Варіант A: без seller у сідах)
    let (vault_pda, bump) = Pubkey::find_program_address(
        &[b"vault".as_ref(), &escrow_data.trade_id12],
        program_id,
    );
    if &vault_pda != vault_acc.key {
        msg!("vault_pda mismatch");
        return Err(ProgramError::InvalidSeeds);
    }
    let signer_seeds: &[&[u8]] = &[
        b"vault".as_ref(),
        &escrow_data.trade_id12[..],
        &[bump],
    ];

    // --- переказ SOL: vault_pda -> seller
    invoke_signed(
        &system_instruction::transfer(vault_acc.key, seller_acc.key, escrow_data.amount),
        &[vault_acc.clone(), seller_acc.clone(), system_program_acc.clone()],
        &[signer_seeds],
    )?;

    // --- оновлюємо статус
    escrow_data.status = EscrowStatus::Released as u8;
    escrow_data.serialize(&mut &mut escrow_acc.data.borrow_mut()[..])?;

    msg!("Escrow Released: trade_id={:?}", escrow_data.trade_id12);

    try_optional_close_after_terminal(
        program_id,
        escrow_acc.clone(),
        vault_acc.clone(),
        system_program_acc.clone(),
        benef_acc.clone(),
        &mut escrow_data,
        false,
    )?;

    Ok(())
}

/// === 3. REFUND_ESCROW ===
fn refund_escrow(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    // [0] escrow_account (PDA, writable, owned by program)
        // [1] vault_pda     (PDA, writable, system-owned)
        // [2] buyer         (readonly)           // НЕ signer
        // [3] authority     (signer)             // БОТ
        // [4] system_program

        let [escrow_acc,
                 vault_acc,
                 buyer_acc,
                 authority_acc,
                 sys_prog_acc,
                 benef_acc,
                 ..] = accounts
            else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };

    if escrow_acc.owner != program_id {
            msg!("escrow_acc not owned by this program");
            return Err(ProgramError::IncorrectProgramId);
        }
        if !authority_acc.is_signer {
            msg!("Missing required signature: authority");
            return Err(ProgramError::MissingRequiredSignature);
        }
        if *sys_prog_acc.key != system_program::id() {
            msg!("system_program key mismatch");
            return Err(ProgramError::IncorrectProgramId);
        }

    let mut escrow_data = EscrowData::try_from_slice(&escrow_acc.data.borrow())?;
    if escrow_data.status != EscrowStatus::Paid as u8 && escrow_data.status != EscrowStatus::Pending as u8 {
        msg!("Invalid status for refund");
        return Err(ProgramError::InvalidAccountData);
    }
    if *buyer_acc.key != escrow_data.buyer {
        msg!("Unauthorized");
        return Err(ProgramError::IllegalOwner);
    }

    let (vault_pda, bump) = Pubkey::find_program_address(&[b"vault".as_ref(), &escrow_data.trade_id12], program_id); // NEW
        if &vault_pda != vault_acc.key { return Err(ProgramError::InvalidSeeds); } // NEW
        let signer_seeds: &[&[u8]] = &[b"vault".as_ref(), &escrow_data.trade_id12, &[bump]]; // NEW

        invoke_signed(
            &system_instruction::transfer(vault_acc.key, buyer_acc.key, escrow_data.amount), // CHANGED
            &[vault_acc.clone(), buyer_acc.clone(), sys_prog_acc.clone()],
            &[signer_seeds],
        )?;

    escrow_data.status = EscrowStatus::Refunded as u8;
    escrow_data.serialize(&mut &mut escrow_acc.data.borrow_mut()[..])?;
    msg!("Escrow Refunded: trade_id={:?}", escrow_data.trade_id12);
    try_optional_close_after_terminal(
        program_id,
        escrow_acc.clone(),
        vault_acc.clone(),
        sys_prog_acc.clone(),
        benef_acc.clone(),
        &mut escrow_data,
        false,
    )?;

        Ok(())
    }

/// === 4. auto_release_escrow ===
fn auto_release_escrow(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    // [0] escrow_account (PDA, writable, owner = program_id)
    // [1] vault_pda     (PDA, writable, owner = SystemProgram)
    // [2] authority     (signer == AUTHORITY_PUBKEY)
    // [3] seller        (writable, == escrow_data.seller)
    // [4] system_program

    let [escrow_acc,
             vault_acc,
             seller_acc,
             authority_acc,
             system_program,
             benef_acc,
             ..] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

    // --- базові перевірки власників / system_program ---
    if escrow_acc.owner != program_id {
        msg!("auto_release_escrow:ERROR:escrow_acc not owned by this program");
        return Err(ProgramError::IncorrectProgramId);
    }
    if system_program.key != &solana_program::system_program::id() {
        msg!("auto_release_escrow:ERROR:Invalid system_program account");
        return Err(ProgramError::IncorrectProgramId);
    }

    // детальний лог Writable для всіх 5 акаунтів

    if !escrow_acc.is_writable || !vault_acc.is_writable || !seller_acc.is_writable {
        msg!("auto_release_escrow:ERROR:Some accounts are not writable");
        msg!(
                "auto_release_escrow:ERROR:Writable flags => escrow:{}, vault:{}, authority:{}, seller:{}, system:{}",
                escrow_acc.is_writable,
                vault_acc.is_writable,
                authority_acc.is_writable,
                seller_acc.is_writable,
                system_program.is_writable
            );
        return Err(ProgramError::InvalidAccountData);
    }

    // явний лог перед MissingRequiredSignature
    if !authority_acc.is_signer {
        msg!("auto_release_escrow:ERROR:Authority did not sign");
        return Err(ProgramError::MissingRequiredSignature);
    }
    if *authority_acc.key != AUTHORITY_PUBKEY {
        msg!("auto_release_escrow:ERROR:auto_release: unauthorized caller");
        return Err(ProgramError::IllegalOwner);
    }

    // --- завантаження ескроу ---
    let mut escrow_data = EscrowData::try_from_slice(&escrow_acc.data.borrow())?;

    // перевірка сидів для escrow_acc: ["escrow", buyer, seller, trade_id[..8]]
   let trade_id_bytes12 = &escrow_data.trade_id12;
   let (expected_escrow_pda, _) =
       Pubkey::find_program_address(&[b"escrow".as_ref(), &trade_id_bytes12[..]], program_id);

    if escrow_acc.key != &expected_escrow_pda {
        msg!("auto_release_escrow:ERROR:escrow_pda mismatch");
        return Err(ProgramError::InvalidSeeds);
    }

    let duration_sec: u64 = if data.len() >= 8 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[..8]);
            u64::from_le_bytes(buf)
        } else {
            DEFAULT_AUTORELEASE_SECS
        };

    // уточнені повідомлення
    if escrow_data.status != EscrowStatus::Paid as u8 {
        msg!("auto_release_escrow:ERROR:Status should be Paid for auto release");
        return Err(ProgramError::InvalidAccountData);
    }
    if seller_acc.key != &escrow_data.seller {
        msg!("auto_release_escrow:ERROR:Given Seller to escrow Seller mismatch");
        return Err(ProgramError::InvalidAccountData);
    }

    // --- тайм-аут ---
        let now = Clock::get()?.unix_timestamp;
        let reference_ts = escrow_data.paid_at;
        let elapsed = now.saturating_sub(reference_ts);
        if reference_ts == 0 || elapsed < (duration_sec as i64) {
            msg!(
                "auto_release_escrow:ERROR:Not timed out (elapsed={}s, need={}s, ref=paid_at={} created_at={})",
                elapsed, duration_sec, escrow_data.paid_at, escrow_data.created_at
            );
            return Err(ProgramError::Custom(123));
        }

    // --- перевірка сидів для vault_pda ---
    let (vault_pda, vbump) =
        Pubkey::find_program_address(&[b"vault".as_ref(), &trade_id_bytes12[..]], program_id);
    if vault_acc.key != &vault_pda {
        msg!("auto_release_escrow:ERROR:vault_pda mismatch");
        return Err(ProgramError::InvalidSeeds);
    }
    let vault_signer_seeds: &[&[u8]] =
        &[b"vault".as_ref(), &trade_id_bytes12[..], &[vbump]];

    // детальний лог про недостатній баланс
    let vault_lamports = **vault_acc.lamports.borrow();
    if vault_lamports < escrow_data.amount {
        msg!(
            "auto_release_escrow:ERROR:Insufficient vault balance: vault={} lamports, required={}",
            vault_lamports,
            escrow_data.amount
        );
        return Err(ProgramError::InsufficientFunds);
    }


    let t = escrow_data.trade_id12;
    msg!(
        "auto_release_escrow:trade_id bytes = [{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}]",
        t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8], t[9], t[10], t[11]
    );
    // --- трансфер з vault_pda -> seller ---
    invoke_signed(
        &system_instruction::transfer(vault_acc.key, seller_acc.key, escrow_data.amount),
        &[vault_acc.clone(), seller_acc.clone(), system_program.clone()],
        &[vault_signer_seeds],
    )?;

    escrow_data.status = EscrowStatus::AutoReleased as u8;
    escrow_data.serialize(&mut &mut escrow_acc.data.borrow_mut()[..])?;
    msg!("auto_release_escrow:Escrow AutoReleased: trade_id={:?}", escrow_data.trade_id12);


    try_optional_close_after_terminal(
        program_id,
        escrow_acc.clone(),
        vault_acc.clone(),
        system_program.clone(),
        benef_acc.clone(),
        &mut escrow_data,
        false,
    )?;

    Ok(())
}

/// === 5. CLOSE_ESCROW ===
fn close_escrow(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    // [0] escrow_account (PDA, w, owner=this program)
    // [1] vault_pda      (PDA, w, system-owned, space=0)
    // [2] beneficiary    (w)   MUST be FIXED_BENEFICIARY_PUBKEY
    // [3] authority      (signer == AUTHORITY_PUBKEY)
    // [4] system_program

    let mut it = accounts.iter();
    let escrow_acc  = next_account_info(&mut it)?; // [0]
    let vault_acc   = next_account_info(&mut it)?; // [1]
    let beneficiary = next_account_info(&mut it)?; // [2]
    let authority   = next_account_info(&mut it)?; // [3]
    let sysprog     = next_account_info(&mut it)?; // [4]

    if escrow_acc.owner != program_id { return Err(ProgramError::IncorrectProgramId); }
    if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }
    if *authority.key != AUTHORITY_PUBKEY { return Err(ProgramError::IllegalOwner); }
    if beneficiary.key != &FIXED_BENEFICIARY{ return Err(ProgramError::IllegalOwner); }
    if *sysprog.key != solana_program::system_program::ID { return Err(ProgramError::IncorrectProgramId); }

    let mut escrow_data = EscrowData::try_from_slice(&escrow_acc.data.borrow())?;

    // дрен vault -> treasury
    let (vault_pda, bump) = Pubkey::find_program_address(
        &[b"vault".as_ref(), &escrow_data.trade_id12], program_id
    );
    if &vault_pda != vault_acc.key { return Err(ProgramError::InvalidSeeds); }
    let signer_seeds: &[&[u8]] = &[b"vault".as_ref(), &escrow_data.trade_id12, &[bump]];

    let vault_balance = **vault_acc.lamports.borrow();
    if vault_balance > 0 {
        invoke_signed(
            &system_instruction::transfer(vault_acc.key, beneficiary.key, vault_balance),
            &[vault_acc.clone(), beneficiary.clone(), sysprog.clone()],
            &[signer_seeds],
        )?;
        msg!("close_escrow: drained {} from vault", vault_balance);
    }

    // повернення ренти з escrow і деінит
    let escrow_balance = **escrow_acc.lamports.borrow();
    if escrow_balance > 0 {
        **beneficiary.lamports.borrow_mut() = beneficiary
            .lamports()
            .checked_add(escrow_balance)
            .ok_or(ProgramError::Custom(0xdead))?;
        **escrow_acc.lamports.borrow_mut() = 0;
        msg!("close_escrow: escrow rent transferred");
    }

    if escrow_data.is_initialized {
        escrow_data.is_initialized = false;
        // escrow_data.serialize(&mut &mut escrow_acc.data.borrow_mut()[..])?; // опційно
        let _ = escrow_acc.realloc(0, false);
        msg!("close_escrow: escrow deinitialized & freed");
    } else {
        msg!("close_escrow: escrow already deinitialized");
    }

    Ok(())
}

// === 6. CLOSE_VAULT ===
// Закриває ТІЛЬКИ vault_pda: дренує всі лампорти на beneficiary.
// Escrow data-акаунт НЕ змінюється.
fn close_vault(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    // [0] escrow_account (ro)
    // [1] vault_pda      (w, system-owned)
    // [2] beneficiary    (w == FIXED_BENEFICIARY_PUBKEY)
    // [3] authority      (signer == AUTHORITY_PUBKEY)
    // [4] system_program

    let mut it = accounts.iter();
    let escrow_acc  = next_account_info(&mut it)?; // [0]
    let vault_acc   = next_account_info(&mut it)?; // [1]
    let beneficiary = next_account_info(&mut it)?; // [2]
    let authority   = next_account_info(&mut it)?; // [3]
    let sysprog     = next_account_info(&mut it)?; // [4]

    if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }
    if *authority.key != AUTHORITY_PUBKEY { return Err(ProgramError::IllegalOwner); }
    if beneficiary.key != &FIXED_BENEFICIARY { return Err(ProgramError::IllegalOwner); }
    if *sysprog.key != solana_program::system_program::ID { return Err(ProgramError::IncorrectProgramId); }

    let escrow_data = EscrowData::try_from_slice(&escrow_acc.data.borrow())?;

    let (derived_vault, bump) = Pubkey::find_program_address(
        &[b"vault".as_ref(), &escrow_data.trade_id12], program_id
    );
    if &derived_vault != vault_acc.key { return Err(ProgramError::InvalidSeeds); }
    let signer_seeds: &[&[u8]] = &[
        b"vault".as_ref(),
        &escrow_data.trade_id12,
        &[bump],
    ];

    let lamports = **vault_acc.lamports.borrow();
    if lamports > 0 {
        invoke_signed(
            &system_instruction::transfer(vault_acc.key, beneficiary.key, lamports),
            &[vault_acc.clone(), beneficiary.clone(), sysprog.clone()],
            &[signer_seeds],
        )?;
        msg!("close_vault: drained {} lamports to treasury", lamports);
    } else {
        msg!("close_vault: vault already empty");
    }

    Ok(())
}

#[cfg(feature = "test")]
pub fn process_test_patch_created_at(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    // payload: [250 | trade_id12 (12 bytes) | new_created_at: i64 LE (8 bytes)]
    const OP: u8 = 250;
    if data.len() < 1 + 12 + 8 || data[0] != OP {
        msg!("Invalid payload for test_patch: len={}, op={}", data.len(), data.get(0).copied().unwrap_or(0));
        return Err(ProgramError::InvalidInstructionData);
    }

    let trade_id12_slice = &data[1..1 + 12];
    let mut trade_id12 = [0u8; 12];
    trade_id12.copy_from_slice(trade_id12_slice);

    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&data[1 + 12..1 + 12 + 8]);
    let new_created_at = i64::from_le_bytes(ts_bytes);

    // Accounts:
    // [0] escrow_account (writable, owned by this program)
    // [1] authority (signer == AUTHORITY_PUBKEY)
    let mut it = accounts.iter();
    let escrow_acc   = next_account_info(&mut it)?; // [0]
    let authority_acc= next_account_info(&mut it)?; // [1]

    if escrow_acc.owner != program_id {
        msg!("test_patch: escrow_acc not owned by this program");
        return Err(ProgramError::IncorrectProgramId);
    }
    if !escrow_acc.is_writable {
        msg!("test_patch: escrow_acc not writable");
        return Err(ProgramError::InvalidAccountData);
    }
    if !authority_acc.is_signer {
        msg!("test_patch: authority did not sign");
        return Err(ProgramError::MissingRequiredSignature);
    }
    if *authority_acc.key != AUTHORITY_PUBKEY {
        msg!("test_patch: unauthorized caller");
        return Err(ProgramError::IllegalOwner);
    }

    // PDA check to ensure escrow_acc matches given trade_id12
    let (expected_escrow, _) = Pubkey::find_program_address(&[b"escrow".as_ref(), &trade_id12], program_id);
    if escrow_acc.key != &expected_escrow {
        msg!("test_patch: escrow_pda mismatch for given trade_id12");
        return Err(ProgramError::InvalidSeeds);
    }

    // patch
    let mut escrow_data = EscrowData::try_from_slice(&escrow_acc.data.borrow())?;
    if !escrow_data.is_initialized {
        msg!("test_patch: escrow not initialized");
        return Err(ProgramError::UninitializedAccount);
    }
    if escrow_data.trade_id12 != trade_id12 {
        msg!("test_patch: state trade_id12 mismatch payload");
        return Err(ProgramError::InvalidAccountData);
    }

    escrow_data.created_at = new_created_at;
    escrow_data.serialize(&mut &mut escrow_acc.data.borrow_mut()[..])?;
    msg!("Patched created_at to {}", new_created_at);
    Ok(())
}

// === 7. SET BUYER WALLET ===
/// Accounts:
/// [0] escrow_pda (writable, owned by this program)
/// [1] bot_authority (може бути переданий як signer з клієнта; тут ми перевіряємо лише ключ)
///
fn set_buyer_wallet(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let acc_iter = &mut accounts.iter();
    let escrow_acc = next_account_info(acc_iter)?; // [0]
    let bot_auth   = next_account_info(acc_iter)?; // [1]

    if escrow_acc.owner != program_id {
        msg!("escrow_acc not owned by this program");
        return Err(ProgramError::IncorrectProgramId);
    }

    if bot_auth.key != &AUTHORITY_PUBKEY {
        msg!("unauthorized: signer is not BOT_AUTHORITY_PUBKEY");
        return Err(ProgramError::IllegalOwner);
    }
    if !bot_auth.is_signer {
        msg!("bot authority must sign");
        return Err(ProgramError::MissingRequiredSignature);
    }

    if data.len() != 32 {
        msg!("set_buyer_wallet: invalid data len {}, expected 32", data.len());
        return Err(ProgramError::InvalidInstructionData);
    }
    let new_buyer = Pubkey::new_from_array(
        data.try_into().map_err(|_| ProgramError::InvalidInstructionData)?
    );

    let mut escrow_data = EscrowData::try_from_slice(&escrow_acc.data.borrow())?;

    let (expected_escrow, _) = Pubkey::find_program_address(
        &[b"escrow".as_ref(), &escrow_data.trade_id12],
        program_id,
    );
    if escrow_acc.key != &expected_escrow {
        msg!("escrow_pda mismatch");
        return Err(ProgramError::InvalidSeeds);
    }


    if new_buyer == Pubkey::default() {
        msg!("new_buyer cannot be default (111...)");
        return Err(ProgramError::InvalidInstructionData);
    }

    escrow_data.buyer = new_buyer;
    escrow_data.serialize(&mut &mut escrow_acc.data.borrow_mut()[..])?;
    msg!("Buyer set for trade_id={:?} -> {:?}", escrow_data.trade_id12, new_buyer);

    Ok(())
}

// === 8. mark_paid ===
// Accounts:
// [0] escrow_pda   (w, owned by this program)
// [1] vault_pda    (r, system-owned)
// [2] system_program
pub fn mark_paid(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    use solana_program::{program_error::ProgramError, system_program, sysvar::rent::Rent};

    let acc_iter = &mut accounts.iter();
    let escrow_acc        = next_account_info(acc_iter)?; // [0]
    let vault_acc         = next_account_info(acc_iter)?; // [1]
    let system_program_acc= next_account_info(acc_iter)?; // [2]

    if escrow_acc.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    if *system_program_acc.key != system_program::id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    if vault_acc.owner != system_program_acc.key {
        return Err(ProgramError::IncorrectProgramId);
    }

    let mut escrow = EscrowData::try_from_slice(&escrow_acc.data.borrow())?;
    if !escrow.is_initialized {
        return Err(ProgramError::UninitializedAccount);
    }
    if escrow.status != EscrowStatus::Pending as u8 {
        msg!("mark_paid allowed only from Pending");
        return Err(ProgramError::InvalidAccountData);
    }

    // Перевірка PDA адреси для vault (Варіант A)
    let (vault_pda, _) = Pubkey::find_program_address(
        &[b"vault".as_ref(), &escrow.trade_id12],
        program_id
    );
    if &vault_pda != vault_acc.key {
        return Err(ProgramError::InvalidSeeds);
    }

    // Баланс vault мінус rent >= очікуваної суми
    let rent_min = Rent::get()?.minimum_balance(0);
    let vault_net = vault_acc.lamports().saturating_sub(rent_min);
    if vault_net < escrow.amount {
        msg!("insufficient funds in vault: have {:?}, need {:?}", vault_net, escrow.amount);
        return Err(ProgramError::InsufficientFunds);
    }

    if escrow.paid_at == 0 {
        escrow.paid_at = Clock::get()?.unix_timestamp;
    }

    escrow.status = EscrowStatus::Paid as u8;
    escrow.serialize(&mut &mut escrow_acc.data.borrow_mut()[..])?;
    msg!("Escrow Marked Paid: trade_id={:?}, amount={:?}", escrow.trade_id12, escrow.amount);
    Ok(())
}