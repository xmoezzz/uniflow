class Vault {
    int *secret;
public:
    int *expose() { return secret; }
};
