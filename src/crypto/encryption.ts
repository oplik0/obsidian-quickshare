import {
	encryptString as _encryptString,
	masterKeyToString,
	generateRandomKey,
	base64ToArrayBuffer,
} from "./crypto";

export interface EncryptedString {
	ciphertext: string;
	key: string;
	iv: string;
	/** @deprecated Please use GCM with IV instead. */
	hmac?: string;
}

export async function encryptString(
	plaintext: string,
	existingKey?: string,
	existingIv?: string
): Promise<EncryptedString> {
	if (existingKey && existingIv) {
		return encryptWithKey(plaintext, existingKey, existingIv);
	}
	const key = await generateRandomKey();
	const { ciphertext, iv } = await _encryptString(plaintext, key);
	return { ciphertext, iv, key: masterKeyToString(key).slice(0, 43) };
}

export async function encryptWithKey(
	plaintext: string,
	key: string,
	iv: string
):  Promise<EncryptedString> {
	const keyBuffer = base64ToArrayBuffer(key);
	const ivBuffer = new Uint8Array(base64ToArrayBuffer(iv));
	const { ciphertext } = await _encryptString(plaintext, keyBuffer, ivBuffer);
	return { ciphertext, iv, key };
}
