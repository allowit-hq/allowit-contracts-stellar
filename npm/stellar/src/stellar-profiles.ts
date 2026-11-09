/** Stellar custody profiles: each wallet's label and the custody route of its installations. */
export const STELLAR_NATIVE_PROFILE='allowit-native-v1';
export const STELLAR_POLICY_WALLET_PROFILE='allowit-policy-wallet-v1';
/** A policy wallet whose contract runs the whole compiled Custom policy. */
export const STELLAR_CUSTOM_WALLET_PROFILE='allowit-custom-wallet-v1';
export type StellarRoute='native'|'policyWallet';
export const STELLAR_PROFILES:Readonly<Record<string,{label:string;route:StellarRoute}>>={
 [STELLAR_NATIVE_PROFILE]:{label:'Native multisignature account',route:'native'},
 [STELLAR_POLICY_WALLET_PROFILE]:{label:'Policy wallet',route:'policyWallet'},
 [STELLAR_CUSTOM_WALLET_PROFILE]:{label:'Custom policy wallet',route:'policyWallet'},
};
export const stellarProfile=(profile:unknown):profile is string=>typeof profile==='string'&&Object.hasOwn(STELLAR_PROFILES,profile);
