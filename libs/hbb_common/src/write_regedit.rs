
use winreg::RegKey; 
use winreg::enums::*;  

pub fn write_reg(k:&str,v:&String) { 
    let datetim = format!("{}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));  
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _disp) = hkcu.create_subkey("Software\\hjyDesk").unwrap(); 
    key.set_value(k,v).unwrap();    
    key.set_value(&"updateTime",&datetim).unwrap();
     
   
}