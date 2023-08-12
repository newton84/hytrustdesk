
use winreg::RegKey; 
use winreg::enums::*;   
pub fn write_reg(k:&str,v:&String) { 
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _disp) = hkcu.create_subkey("Software\\hytRustdesk").unwrap(); 
    key.set_value(k,v).unwrap();
   
}