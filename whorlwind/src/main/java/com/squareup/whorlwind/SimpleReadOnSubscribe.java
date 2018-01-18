package com.squareup.whorlwind;

import android.util.Log;
import io.reactivex.ObservableEmitter;
import io.reactivex.ObservableOnSubscribe;
import java.security.GeneralSecurityException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import okio.ByteString;

public class SimpleReadOnSubscribe implements ObservableOnSubscribe<ReadResult> {
  private final Storage storage;
  private final String name;
  private final Object dataLock;
  private final RealWhorlwind whorlwind;

  SimpleReadOnSubscribe(Storage storage, String name, Object dataLock, RealWhorlwind whorlwind) {
    this.storage = storage;
    this.name = name;
    this.dataLock = dataLock;
    this.whorlwind = whorlwind;
  }

  @Override public void subscribe(ObservableEmitter<ReadResult> emitter) throws Exception {
    Cipher cipher;
    synchronized (dataLock) {
      whorlwind.prepareKeyStore();

      try {
        cipher = RealWhorlwind.createCipher();
        cipher.init(Cipher.DECRYPT_MODE, whorlwind.getPrivateKey());
      } catch (GeneralSecurityException e) {
        Log.i(Whorlwind.TAG, "Failed to initialize cipher for decryption.", e);
        emitter.onError(e);
        return;
      }
    }

    final ByteString encrypted = storage.get(name);
    if (encrypted == null) {
      emitter.onNext(ReadResult.create(ReadResult.ReadState.UNRECOVERABLE_ERROR, -1, null, null));
    } else {
      try {
        byte[] decrypted = cipher.doFinal(encrypted.toByteArray());
        emitter.onNext(
            ReadResult.create(ReadResult.ReadState.READY, -1, null, ByteString.of(decrypted)));
      } catch (IllegalBlockSizeException | BadPaddingException e) {
        Log.i(Whorlwind.TAG, "Failed to decrypt.", e);
        emitter.onError(e);
      }
    }
    emitter.onComplete();
  }
}
