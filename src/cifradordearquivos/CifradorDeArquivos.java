package cifradordearquivos;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 *
 * @author ricardom
 */
public class CifradorDeArquivos {
    
    private static final int MAC_SIZE = 128;

    public static void main(String[] args) throws Exception {
        CifradorDeArquivos that = new CifradorDeArquivos();
        Scanner input = new Scanner(System.in);
        SecureRandom randomizador = SecureRandom.getInstance("SHA1PRNG", "SUN");
        byte[] iv = new byte[16];
        randomizador.nextBytes(iv);                
        String senha, salt, chaveDerivada, nomeArquvio, hashNomeArquivo;
        File chaveiro = new File("Chaveiro.txt");
        
        if (chaveiro.exists()) {
            System.out.println("Chaveiro ja existe");
        } else {
            System.out.println("Digite a senha do chaveiro: ");
            senha = input.nextLine();
            criaChaveiro();
            System.out.println("Novo chaveiro foi criado");
        }
            
        
        System.out.println("Digite o nome do arquivo: ");
        nomeArquvio = input.nextLine();
        File file = new File(nomeArquvio);
        
        if(!file.exists()) {
            System.out.println("Arquivo não encontrado");
            return;
        }
        
        System.out.println("Digite a senha (uma chave será derivada a partir dela): ");
        senha = input.nextLine();
                
        try{
            salt = that.getSalt();
            
            chaveDerivada = generateDerivedKey(senha, salt, 10000);
            hashNomeArquivo = generateDerivedKey(senha, salt, 10000);
            
            System.out.println("Chave derivada da senha = " + chaveDerivada );
        } catch (Exception e) {
            System.out.print(e.getMessage());     
            chaveDerivada = null;
            hashNomeArquivo = null;
        }
        
        if(chaveDerivada == null) return;

        KeyParameter key = new KeyParameter(chaveDerivada.getBytes());
        AEADParameters params = new AEADParameters(key, MAC_SIZE, iv);
        
        cifraArquivo(file, params);
        
        escreveNoChaveiro(hashNomeArquivo, chaveDerivada);
        
    }
    
    public String getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        //SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return Hex.encodeHexString(salt);
    }
    
    public static void cifraArquivo(File arquivo, AEADParameters params) {
        GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
        try {
            byte[] file = IOUtils.toByteArray(arquivo.getName());
            gcm.init(true, params);
            int outsize = gcm.getOutputSize(file.length);
            byte[] outc = new byte[outsize];
            int lengthOutc = gcm.processBytes(file, 0, file.length, outc, 0);
            gcm.doFinal(outc, lengthOutc);
            BufferedWriter writer = null;
            writer = new BufferedWriter(new FileWriter(arquivo));    
            writer.write(org.bouncycastle.util.encoders.Hex.toHexString(outc));
            writer.close();
            System.out.println("Arquivo "+ arquivo.getName() + " foi cifrado");
        } catch (Exception e) {
            System.out.println("Erro lendo arquivo: "+ arquivo.getName());
        }        
    }
    
    public static String generateDerivedKey(String password, String salt, Integer iterations) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, 128);
        SecretKeyFactory pbkdf2 = null;
        String derivedPass = null;
        try {
            pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            SecretKey sk = pbkdf2.generateSecret(spec);
            derivedPass = Hex.encodeHexString(sk.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return derivedPass;
    }
    
    public static void criaChaveiro() {
        GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
        
        
        
        BufferedWriter writer = null;
        try {
            File chaveiro = new File("Chaveiro.txt");
            writer = new BufferedWriter(new FileWriter(chaveiro));    
            writer.write("Start of Keystack");
            writer.close();
            IOUtils.toByteArray("Chaveiro.txt");
            
        } catch (Exception e) {
            e.printStackTrace();
        } 
    }
    
    public static void escreveNoChaveiro (String nome, String chave) {
        String result;
        
        result = System.lineSeparator() + nome + " " + chave;
                
        try {
            Files.write(Paths.get("Chaveiro.txt"), result.getBytes() , StandardOpenOption.APPEND);
        } catch (Exception e) {
            e.printStackTrace();
        } 
    }
    
}