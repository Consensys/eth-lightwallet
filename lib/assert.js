function derivedKey(keystore, pwDerivedKey) {
  if (!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error('Incorrect derived key!');
  }
}

module.exports = {
  derivedKey,
};
