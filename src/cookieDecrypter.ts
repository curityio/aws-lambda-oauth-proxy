/*
 *  Copyright 2022 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
import crypto from 'crypto'
import InvalidTokenHandlerCookieException from "./InvalidTokenHandlerCookieException";

const VERSION_SIZE = 1;
const GCM_IV_SIZE = 12;
const GCM_TAG_SIZE = 16;
const CURRENT_VERSION = 1;

export default async function decryptCookie(
  encryptedbase64value: string,
  encryptionKeyHex: string,
): Promise<string> {
  const allBytes = Buffer.from(
      encryptedbase64value
          .replace(/-/g, "+")
          .replace(/_/g, "/"),
      "base64")

  const minSize = VERSION_SIZE + GCM_IV_SIZE + 1 + GCM_TAG_SIZE

  if (allBytes.length < minSize) {
    throw new InvalidTokenHandlerCookieException("The received cookie has an invalid length")
  }

  const version = allBytes[0]
  if (version != CURRENT_VERSION) {
    throw new InvalidTokenHandlerCookieException("The received cookie has an invalid format")
  }

  let offset = VERSION_SIZE
  const ivBytes = allBytes.slice(offset, offset + GCM_IV_SIZE)

  offset += GCM_IV_SIZE
  const ciphertextBytes = allBytes.slice(offset, allBytes.length - GCM_TAG_SIZE)

  offset = allBytes.length - GCM_TAG_SIZE
  const tagBytes = allBytes.slice(offset, allBytes.length)

  try {

    const encKeyBytes = Buffer.from(encryptionKeyHex, "hex")
    const decipher = crypto.createDecipheriv('aes-256-gcm', encKeyBytes, ivBytes)
    decipher.setAuthTag(tagBytes)

    const decryptedBytes = decipher.update(ciphertextBytes)
    const finalBytes = decipher.final()

    const plaintextBytes = Buffer.concat([decryptedBytes, finalBytes])
    return plaintextBytes.toString()

  } catch(error: any) {
    throw new InvalidTokenHandlerCookieException(error.message)
  }
}


