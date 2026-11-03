/** Stellar custody profiles: each wallet's label and the custody route of its installations. */
export declare const STELLAR_NATIVE_PROFILE = "allowit-stellar-native-v1";
export declare const STELLAR_POLICY_WALLET_PROFILE = "allowit-stellar-policy-wallet-v1";
/** A policy wallet whose contract runs the whole compiled Custom policy. */
export declare const STELLAR_CUSTOM_WALLET_PROFILE = "allowit-stellar-custom-wallet-v1";
export type StellarRoute = 'native' | 'policyWallet';
export declare const STELLAR_PROFILES: Readonly<Record<string, {
    label: string;
    route: StellarRoute;
}>>;
export declare const stellarProfile: (profile: unknown) => profile is string;
