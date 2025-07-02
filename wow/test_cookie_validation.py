
import asyncio
from bot.data_collector import RobloxValidator

async def test_cookie_validation():
    """Test the cookie validation with your provided cookie"""
    
    # Your cookie with the warning prefix
    test_cookie = "_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_CAEaAhAB.CFDC7278B62C64C6597B78AD2105706B606D2EB86992CF354E7958129CAEF9FAF456B009BC3E11B85CE20FF1A840E74D439CFBE12A4868315E2D81EA7088E5E3A70E48E4F915D35C2CD719004FD134142F682FD41BC3A8338ACDA9315D740C1FC4DF67F9F101B309CB2D9E4A782447E82F2E71A17708B79AC604E53D2AAAE165DDB47D1ED5528421C7D9308E362755C645754EDD5F834F44C0C0B835DB82B0F8E173ABD12241AAF1179B1DC89FA1853B8CDC10858A413FBB5F8DDCC052BD554E71CF34169629FB4D21320C57723A8E4E14E163112AECD9D66F9EDD1CD99CAEB5A5C25B6FEB4B76EF3228A3AE078BF038F36485707CAFBF2196EA395E931974AB86FDF9058EE7DC089E22503150241D84990F5D50FE7A8C435029C622C6D17FA8BD3503F59A96B2EFDF72D827DC637940AE74039F134BE2C7E4287C257AA24D11B029A358AC82934C2E7657062FFD4543B0C015319774B5686BD194DC24E7DA112869899EE86C6012F0999A38D03B701027CCD7CC94495F15A453CA9CA5ABE92F704BD17D13C01A9A293DACCB156B3A656C6959550CA8CF77F8134F63FF472CD480FDAF2A8D625C9719EBE47CE0F5A8C56466ED495D79C3D0BE76236284A07B236FC86E12E9063A24493745E957827BBAE1BC0B3AA54534547A829F6D69DFA8548F0F8564ADC7FB12D02B3507856BD0214B45ECEA5BE4595871E75647ABA241BEC1EDFE39E522B6D0996B767E3954D42AB771E3F6EE8DEC483EFB49CF45880A0B04F1E248CCD61EF28EF0E8EEC1FE7E1C65F64DB30D6A14D74744871B9C885434896C708CE584EA4B19102A7A341A42EC69298824"
    
    print("Testing Roblox cookie validation...")
    print("=" * 50)
    
    # Initialize the validator
    validator = RobloxValidator()
    
    # Test the validation
    result = await validator.validate_cookie(test_cookie)
    
    print(f"Cookie validation result:")
    print(f"Valid: {result['valid']}")
    
    if result['valid']:
        print(f"Username: {result.get('username', 'N/A')}")
        print(f"User ID: {result.get('user_id', 'N/A')}")
        print(f"Robux Balance: {result.get('robux_balance', 'N/A')}")
        print(f"Premium: {result.get('is_premium', 'N/A')}")
        print(f"Status Code: {result.get('status_code', 'N/A')}")
    else:
        print(f"Error: {result.get('error', 'N/A')}")
        print(f"Status Code: {result.get('status_code', 'N/A')}")
    
    print(f"Validation Timestamp: {result.get('validation_timestamp', 'N/A')}")
    
    # Test cookie format handling
    print("\n" + "=" * 50)
    print("Cookie format analysis...")
    print(f"Full cookie length: {len(test_cookie)}")
    print(f"Contains warning prefix: {'_|WARNING:-DO-NOT-SHARE-THIS.' in test_cookie}")
    
    if "_|WARNING:-DO-NOT-SHARE-THIS." in test_cookie:
        cookie_parts = test_cookie.split("CAEaAhAB.")
        if len(cookie_parts) > 1:
            extracted_token = "CAEaAhAB." + cookie_parts[-1]
            print(f"Extracted token length: {len(extracted_token)}")
            print(f"Extracted token starts with CAEaAhAB: {extracted_token.startswith('CAEaAhAB')}")
            print(f"First 50 chars of token: {extracted_token[:50]}...")
    
if __name__ == "__main__":
    asyncio.run(test_cookie_validation())
