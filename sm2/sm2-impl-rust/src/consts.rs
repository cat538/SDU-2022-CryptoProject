use crate::error::{Sm2Error,Sm2Result};

// 椭圆曲线六元组: (p,a,b,G,b,h)
// 其中`p`为素数域的阶, `a`, `b`为曲线系数, `G`为生成元, `n`为曲线群的阶, `h`为co-factor
// 对于sm2:
// p = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF
// a = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFC
// b = 0x28E9FA9E_9D9F5E34_4D5A9E4B_CF6509A7_F39789F5_15AB8F92_DDBCBD41_4D940E93
// n = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_7203DF6B_21C6052B_53BBF409_39D54123
// Gx= 0x32C4AE2C_1F198119_5F990446_6A39C994_8FE30BBF_F2660BE1_715A4589_334C74C7
// Gy= 0xBC3736A2_F4F6779C_59BDCEE3_6B692153_D0A9877C_C62A4740_02DF32E5_2139F0A0

pub const P:[u64;4] = [0xFFFFFFFE_FFFFFFFF, 0xFFFFFFFF_FFFFFFFF, 0xFFFFFFFF_00000000, 0xFFFFFFFF_FFFFFFFF];
pub const A:[u64;4] = [0xFFFFFFFE_FFFFFFFF, 0xFFFFFFFF_FFFFFFFF, 0xFFFFFFFF_00000000, 0xFFFFFFFF_FFFFFFFC];
pub const B:[u64;4] = [0x28E9FA9E_9D9F5E34, 0x4D5A9E4B_CF6509A7, 0xF39789F5_15AB8F92, 0xDDBCBD41_4D940E93];
pub const N:[u64;4] = [0xFFFFFFFE_FFFFFFFF, 0xFFFFFFFF_FFFFFFFF, 0x7203DF6B_21C6052B, 0x53BBF409_39D54123];
pub const GX:[u64;4]= [0x32C4AE2C_1F198119, 0x5F990446_6A39C994, 0x8FE30BBF_F2660BE1, 0x715A4589_334C74C7];
pub const GY:[u64;4]= [0xBC3736A2_F4F6779C, 0x59BDCEE3_6B692153, 0xD0A9877C_C62A4740, 0x02DF32E5_2139F0A0];

