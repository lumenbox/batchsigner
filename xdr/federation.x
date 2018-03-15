namespace stellar
{

enum CryptoKeyType
{
    KEY_TYPE_ED25519 = 0,
    KEY_TYPE_HASH_TX = 1,
    KEY_TYPE_HASH_X = 2
};

enum PublicKeyType
{
    PUBLIC_KEY_TYPE_ED25519 = KEY_TYPE_ED25519
};

typedef opaque uint256[32];

union PublicKey switch (PublicKeyType type)
{
case PUBLIC_KEY_TYPE_ED25519:
    uint256 ed25519;
};

typedef PublicKey AccountID;

enum MemoType
{
    MEMO_NONE = 0,
    MEMO_TEXT = 1,
    MEMO_ID = 2,
    MEMO_HASH = 3,
    MEMO_RETURN = 4
};

typedef string string64<64>;
typedef unsigned hyper uint64;
typedef opaque Hash[32];

union Memo switch (MemoType type)
{
case MEMO_NONE:
    void;
case MEMO_TEXT:
    string text<28>;
case MEMO_ID:
    uint64 id;
case MEMO_HASH:
    Hash hash; // the hash of what to pull from the content server
case MEMO_RETURN:
    Hash retHash; // the hash of the tx you are rejecting
};

// everything above is defined in Stellar .x files
// from here we ave the custom stuff

struct FederationResponse
{

    string64 stellarAddress; // Stellar uses string32 for domain name, using double for the federation name
    AccountID accountID;
    Memo memo;

    // reserved for future use
    union switch (int v)
    {
    case 0:
        void;
    }
    ext;
};

}
