use anyhow::Result;

pub fn read_ima_log_if_requested(_with_ima: bool) -> Result<Option<Vec<u8>>> {
    Ok(None)
}
