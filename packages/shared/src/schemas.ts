import { z } from "zod";

// Helper regexes
const ALPHANUMERIC_REGEX = /^[a-zA-Z0-9]+$/;
const SIX_DIGITS_REGEX = /^\d{6}$/;
const BASE64_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;

export const RegisterSchema = z.object({
    username: z.string()
        .min(3, "Username must be at least 3 characters")
        .max(50, "Username must be at most 50 characters")
        .regex(ALPHANUMERIC_REGEX, "Username must contain only letters and numbers"),
    password: z.string().min(8, "Password must be at least 8 characters"),
});

export const LoginSchema = z.object({
    username: z.string().min(1, "Username is required"),
    password: z.string().min(1, "Password is required"),
});

export const Enable2faSchema = z.object({
    username: z.string().regex(ALPHANUMERIC_REGEX, "Username must contain only letters and numbers"),
});

export const Verify2faSchema = z.object({
    username: z.string().min(1, "Username is required"),
    token: z.string().regex(SIX_DIGITS_REGEX, "2FA token must be exactly 6 digits"),
    secret: z.string().optional(),
});

export const VerifyPasswordSchema = z.object({
    password: z.string().min(1, "Password is required"),
});

export const DeleteAccountSchema = z.object({
    password: z.string().min(1, "Password is required"),
    totpToken: z.string().regex(SIX_DIGITS_REGEX, "2FA token must be exactly 6 digits").optional().or(z.literal("")),
});

export const SaveVekSchema = z.object({
    encryptedVEK: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
    vekIV: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
    vekAuthTag: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
});

export const SetupRecoverySchema = z.object({
    recoveryKeyHash: z.string().min(1, "Recovery key hash is required"),
    recoveryEncryptedVEK: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
    recoveryVekIV: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
    recoveryVekAuthTag: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
});

export const InitRecoverySchema = z.object({
    recoveryKeyHash: z.string().min(1, "Recovery key hash is required"),
});

export const ResetRecoverySchema = z.object({
    recoveryKeyHash: z.string().min(1, "Recovery key hash is required"),
    newPassword: z.string().min(8, "New password must be at least 8 characters"),
    newEncryptedVEK: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
    newVekIV: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
    newVekAuthTag: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
    newVaultSalt: z.string().min(1, "Vault salt is required"),
    twoFactorSecret: z.string().min(1, "New 2FA secret is required"),
    totpToken: z.string().regex(SIX_DIGITS_REGEX, "2FA token must be exactly 6 digits"),
});

export const CreateVaultItemSchema = z.object({
    encryptedBlob: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
    iv: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
    authTag: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
});

export const UpdateVaultItemSchema = z.object({
    encryptedBlob: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
    iv: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
    authTag: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
});

export const DecryptedVaultItemPayloadSchema = z.object({
    site: z.string().min(1, "Website/Title is required"),
    username: z.string().min(1, "Username is required"),
    password: z.string().min(8, "Password must be at least 8 characters"),
    notes: z.string().optional(),
});

export const ChangeUsernameSchema = z.object({
    newUsername: z.string()
        .min(3, "Username must be at least 3 characters")
        .max(50, "Username must be at most 50 characters")
        .regex(/^[a-zA-Z0-9]+$/, "Username must contain only letters and numbers"),
});

export const ChangePasswordSchema = z.object({
    currentPassword: z.string().min(1, "Current password is required"),
    newPassword: z.string().min(10, "Password must be at least 10 characters")
        .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
        .regex(/[!@#$%^&*(),.?":{}|<>]/, "Password must contain at least one special character"),
    encryptedVEK: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
    vekIV: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
    vekAuthTag: z.string().regex(BASE64_REGEX, "Invalid base64 encoding"),
    newVaultSalt: z.string().min(1, "New vault salt is required"),
});

export const Reset2faSchema = z.object({
    password: z.string().min(1, "Password is required"),
});

export const ClearRecoverySchema = z.object({
    password: z.string().min(1, "Password is required"),
});

