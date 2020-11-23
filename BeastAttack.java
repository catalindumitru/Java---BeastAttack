import java.io.*;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.util.Date;

public class BeastAttack {

    // We keep record of the last time we called the encryption function and the IV that
    // was generated in order to guess future IVs.
    static byte[] lastIV;
    static long lastTime;

    public static void main(String[] args) throws Exception {
        task1();
        task2();
    }

    public static void task1() throws Exception {
        // The length of the plaintext is just the length of the cipherblock
        // minus the length of the IV, because the cipherblock is
        // < iv1,iv2,...,iv8, c1,c2,...c8, ... , c_(8n-7),c_(8n-6),...,c_(8n) >
        // and < ci,c_(i+1),....,c_(i+7) > = E(< m_i + c_(i-8), ... , m_(i+7) + c_(i-1) >).

        byte[] ciphertext = new byte[1024];
        int length = callEncrypt(null, 0, ciphertext);
        System.out.println("The length of the plaintext is " + (length - 8));
        System.out.println("");   

        for (int i = 0; i < 20; i++) {
            byte[] IV = getIV();
            printBytes(IV);
        }

        System.out.println(""); 

        // The IV seems to be linearly dependent on time. After tabulating some IVs,
        // I noticed that the difference between the integer values of two IVs is
        // approximately 5 * the difference between the times they were generated.
    }

    public static void task2() throws Exception {
        byte[] ciphertext = new byte[1024];

        // Keep record of the bytes that were found so far.
        byte[] found = new byte[8];

        System.out.print("The first block of the plaintext is: ");

        // Find each of the bytes of the first block, starting with m1 = m_(8-i).
        for (int i = 7; i >= 0; i--) {
            // Force the prefix <0,0,0,...,0> (i zeros) to get a ciphertext.
            lastTime = System.currentTimeMillis();
            callEncrypt(new byte[i], i, ciphertext);
            lastIV = Arrays.copyOfRange(ciphertext, 0, 8);

            // Keep record of this encryption's IV and second block. We'll
            // use them later for XOR-ing and validation.
            byte[] initIV = lastIV;
            byte[] target = Arrays.copyOfRange(ciphertext, 8, 16);

            byte x = Byte.MAX_VALUE;
            boolean done = false;
            
            // Force the prefix <0,0,0,...,m1,m2,...,m_(7-i),x> for all possible x.
            byte[] prefix = new byte[8];
            for (int j = 0; j < 7-i; j++) {
                prefix[i+j] = found[j];
            }

            while (!done) {
                prefix[7] = x;

                // Predict the IV for the next encryption.
                byte[] predictedIV = predictIV();

                // XOR the prefix with the initial IV and the predicted IV. The latter 
                // should cancel when we call encrypt if we guessed it correctly,
                // leaving initIV[j] ^ prefix[j] which should give us the target block
                // if x is the current m_(8-i) we're looking for.
                byte[] prefixXOR = new byte[8];
                for (int j = 0; j < 8; j++) {
                    prefixXOR[j] = (byte) (predictedIV[j] ^ initIV[j] ^ prefix[j]);
                }

                // Call encrypt with this prefix, getting a trueIV which we'll compare
                // with our guess. We also update lastIV and lastTime for further use.
                lastTime = System.currentTimeMillis();
                callEncrypt(prefixXOR, 8, ciphertext);
                byte[] trueIV = Arrays.copyOfRange(ciphertext, 0, 8);
                lastIV = trueIV;

                // If our guess was correct, we compare the block that x gave with
                // our target.
                if (Arrays.equals(trueIV, predictedIV)) {
                    byte[] block = Arrays.copyOfRange(ciphertext, 8, 16);

                    // If the blocks are equal, we found the next m_(8-i).
                    if (Arrays.equals(block, target)) {
                        done = true;
                        found[7-i] = x;
                        System.out.print((char) x);
                    }
                    // Otherwise, we try another x.
                    else {
                        x--;
                    }
                } // otherwise we make another prediction.
            }
        }

        System.out.println("");
    }


    // a helper method to call the external programme "encrypt" in the current directory
    // the parameters are the plaintext, length of plaintext, and ciphertext; returns length of ciphertext
    static int callEncrypt(byte[] prefix, int prefix_len, byte[] ciphertext) throws IOException {
        HexBinaryAdapter adapter = new HexBinaryAdapter();
        Process process;

        // run the external process (don't bother to catch exceptions)
        if (prefix != null) {
            // turn prefix byte array into hex string
            byte[] p = Arrays.copyOfRange(prefix, 0, prefix_len);
            String PString = adapter.marshal(p);
            process = Runtime.getRuntime().exec("./encrypt " + PString);
        } else {
            process = Runtime.getRuntime().exec("./encrypt");
        }

        // process the resulting hex string
        String CString = (new BufferedReader(new InputStreamReader(process.getInputStream()))).readLine();
        byte[] c = adapter.unmarshal(CString);
        System.arraycopy(c, 0, ciphertext, 0, c.length);
        return (c.length);
    }

    // Predict the next IV using the last one and the last time one was generated.
    static byte[] predictIV() {
        byte[] prediction;
        // time difference
        long diff = System.currentTimeMillis() - lastTime;
        // integer value of lastIV 
        long lastIVtoLong = ByteBuffer.wrap(lastIV).getLong();
        // we want an IV with integer value = lastIVtoLong + diff * 5
        prediction = ByteBuffer.allocate(8).putLong(lastIVtoLong + diff * 5).array();

        return prediction;
    }

    // Call the encryption function and recover the IV.
    // This is only used at the beginning to get an idea about the shape of the IVs.
    static byte[] getIV() throws Exception {
        byte[] ciphertext = new byte[1024];
        callEncrypt(null, 0, ciphertext);
        byte[] IV = Arrays.copyOfRange(ciphertext, 0, 8);

        return IV;
    }

    static void printBytes(byte[] bytes) {
    	for (int i = 0; i < bytes.length; i++)
            System.out.print(String.format("%02x ", bytes[i]));
            
		System.out.println();
	}
}
