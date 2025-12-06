import { generateKeyPair, publicKeyToJWK, getJWKS, keys } from "./CSCE3550_Project";
const jwt = require("jsonwebtoken");

describe("JWT / JWKS Server", () => {

  test("generateKeyPair returns key object with required properties", () => {
    const key = generateKeyPair();
    expect(key).toHaveProperty("kid");
    expect(key).toHaveProperty("publicKey");
    expect(key).toHaveProperty("privateKey");
    expect(key).toHaveProperty("expiresAt");
  });

  test("publicKeyToJWK returns a valid JWK", () => {
    const key = generateKeyPair();
    const jwk = publicKeyToJWK(key.publicKey, key.kid);
    expect(jwk).toHaveProperty("kty", "RSA");
    expect(jwk).toHaveProperty("kid", key.kid);
    expect(jwk).toHaveProperty("use", "sig");
    expect(jwk).toHaveProperty("alg", "RS256");
    expect(jwk).toHaveProperty("n");
    expect(jwk).toHaveProperty("e");
  });

  test("getJWKS returns non-expired keys only", () => {
    const jwks = getJWKS();
    jwks.keys.forEach(jwk => {
      const key = keys.find(k => k.kid === jwk.kid);
      expect(key.expiresAt).toBeGreaterThan(Date.now());
    });
  });

  test("expired key exists if generated", () => {
    const expiredKey = generateKeyPair(true);
    keys.push(expiredKey);
    const foundExpired = keys.find(k => k.expiresAt < Date.now());
    expect(foundExpired).toBeDefined();
  });

  test("JWT can be signed and verified", () => {
    const key = generateKeyPair();
    const payload = { user: "test" };
    const token = jwt.sign(payload, key.privateKey, { algorithm: "RS256" });
    const decoded = jwt.verify(token, key.publicKey, { algorithms: ["RS256"] });
    expect(decoded.user).toBe("test");
  });

});