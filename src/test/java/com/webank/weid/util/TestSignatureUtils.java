/*
 *       Copyright© (2018-2020) WeBank Co., Ltd.
 *
 *       This file is part of weid-java-sdk.
 *
 *       weid-java-sdk is free software: you can redistribute it and/or modify
 *       it under the terms of the GNU Lesser General Public License as published by
 *       the Free Software Foundation, either version 3 of the License, or
 *       (at your option) any later version.
 *
 *       weid-java-sdk is distributed in the hope that it will be useful,
 *       but WITHOUT ANY WARRANTY; without even the implied warranty of
 *       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *       GNU Lesser General Public License for more details.
 *
 *       You should have received a copy of the GNU Lesser General Public License
 *       along with weid-java-sdk.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.webank.weid.util;

import java.math.BigInteger;

import com.lambdaworks.codec.Base64;
import org.bcos.web3j.crypto.ECKeyPair;
import org.bcos.web3j.crypto.Sign;
import org.fisco.bcos.web3j.crypto.Keys;
import org.fisco.bcos.web3j.utils.Numeric;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Test SignatureUtils.
 *
 * @author v_wbjnzhang and chaoxinhu
 */
public class TestSignatureUtils {

    private static final Logger logger = LoggerFactory.getLogger(TestSignatureUtils.class);

    @Test
    public void testSignatureUtils()
        throws Exception {

        ECKeyPair keyPair = DataToolUtils.createKeyPair();
        String str = "hello world...........................yes";
        Sign.SignatureData sigData = DataToolUtils.signMessage(str, keyPair);
        BigInteger publicKey = DataToolUtils.signatureToPublicKey(str, sigData);
        logger.info("publicKey:{} ", publicKey);

        String privateKey =
            "58317564669857453586637110679746575832914889677346283755719850144028639639651";
        Sign.SignatureData sigData2 = DataToolUtils.signMessage(str, privateKey);
        publicKey = DataToolUtils.signatureToPublicKey(str, sigData2);
        logger.info("publicKey:{} ", publicKey);
        System.out.println(publicKey.toString(10));

        boolean result = DataToolUtils.verifySignature(str, sigData2, publicKey);
        Assert.assertTrue(result);

        publicKey = DataToolUtils.publicKeyFromPrivate(new BigInteger(privateKey));
        logger.info("publicKey:{} ", publicKey);

        keyPair = DataToolUtils.createKeyPairFromPrivate(new BigInteger(privateKey));
        logger.info("publicKey:{} ", keyPair.getPublicKey());
        logger.info("privateKey:{}", keyPair.getPrivateKey());

        byte[] serialized = DataToolUtils.simpleSignatureSerialization(sigData);
        Sign.SignatureData newSigData = DataToolUtils.simpleSignatureDeserialization(serialized);
        logger.info(newSigData.toString());

        Sign.SignatureData signatureData = DataToolUtils
            .convertBase64StringToSignatureData(new String(Base64.encode(serialized)));
        logger.info(signatureData.toString());
    }

    @Test
    public void testSecp256k1Base64AndHex() throws Exception {
        org.fisco.bcos.web3j.crypto.ECKeyPair keyPair2 = Keys.createEcKeyPair();
        String correctEncodedBase64Str = org.apache.commons.codec.binary.Base64
            .encodeBase64String(keyPair2.getPublicKey().toByteArray());
        System.out.println("biginteger直接转换toString hex " + keyPair2.getPublicKey().toString(16));
        System.out.println("biginteger的base64 " + correctEncodedBase64Str);
        byte[] pubkey = org.apache.commons.codec.binary.Base64
            .decodeBase64(correctEncodedBase64Str);
        BigInteger bi2 = Numeric.toBigInt(pubkey);
        System.out.println("base64往返转换 " + bi2.toString(16));
        Assert.assertEquals(bi2.toString(16), keyPair2.getPublicKey().toString(16));
        String dex = bi2.toString(10);
        System.out.println("十进制 " + dex);
        BigInteger db = new BigInteger(dex, 10);
        System.out.println("十进制转成的dex " + db.toString(16));
        Assert.assertEquals(db.toString(16), bi2.toString(16));

        String txHexPubKey = "dfa0a3c55931f26ced064a8f6f79770b44e8a04d183d26b1ff71bbf68fa26cfc6601f17fc9fe25a7179206294d9201ea46b435814bc96c9c80b71b17534d55a9";
        //String txBase64 = "APoqbCpDbA9zQANLVHR7IUn2CplkltRCydFdBkGzpoj8WCy+oo0fNF6FH950CygRQ/1anhkOYdC0RLIk4qhpruI=";
        String txBase64 = "9CkBtkl29d9vmWenOConzsUAJr4Q6pc21cDdlTLU2aZsqbgG8eSVfXs9rFV+tCe4mbEu1INjwGCHtiSayHzmhQ==";
        pubkey = org.apache.commons.codec.binary.Base64.decodeBase64(txBase64);
        bi2 = Numeric.toBigInt(pubkey);
        System.out.println("new hex值 " + bi2.toString(16));
        //Assert.assertEquals(bi2.toString(16), txHexPubKey);
        System.out.println("十进制 " + bi2.toString(10));
        System.out.println(org.apache.commons.codec.binary.Base64
            .encodeBase64String(Numeric.hexStringToByteArray(bi2.toString(16))));

        System.out.println();
        // Base64 <> hex conversion
        String hexFrom = Numeric
            .toHexStringNoPrefix(org.apache.commons.codec.binary.Base64.decodeBase64(txBase64));
        System.out.println(hexFrom);
        String base64To = org.apache.commons.codec.binary.Base64
            .encodeBase64String(Numeric.hexStringToByteArray(hexFrom));
        System.out.println(base64To);
        Assert.assertEquals(base64To, org.apache.commons.codec.binary.Base64
            .encodeBase64String(Numeric.hexStringToByteArray(bi2.toString(16))));
    }
}
