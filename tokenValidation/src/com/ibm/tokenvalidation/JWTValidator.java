package com.ibm.tokenvalidation;


import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.InvalidJwtSignatureException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import org.jose4j.keys.resolvers.X509VerificationKeyResolver;

public class JWTValidator {
	static JwtConsumer decoder=null;
    static KeyStore truststore=null;
    static X509Certificate identity=null;
    static X509VerificationKeyResolver x509Resolver=null;
    public static Boolean validateToken(String jwt,String storePath,String pwd,String iss) {
        // String iss="https://esbopendev.isservices.co.za";
        try {
            if(truststore==null){
                truststore = KeyStore.getInstance("JKS");
                //truststore.load(new FileInputStream("e:/genx/work/certs/identity.jks"), "password".toCharArray());
                truststore.load(new FileInputStream(storePath), pwd.toCharArray());
            }
            if(identity==null){
             identity = (X509Certificate) truststore.getCertificate("Identity");
            x509Resolver = new X509VerificationKeyResolver(identity);
            x509Resolver.setTryAllOnNoThumbHeader(true);
            decoder = new JwtConsumerBuilder().setVerificationKeyResolver(x509Resolver)
            		.setAllowedClockSkewInSeconds(180)
                    .setExpectedAudience(iss+"/resources")
                    .setExpectedIssuer(iss)
                    .build();   
            }

            

            //truststore.load(new FileInputStream("C:/BrokerSSL/IIBDEVNEW/isservicestruststore.co.za.jks"), "password".toCharArray());      
            
            JwtClaims claims = decoder.processToClaims(jwt);
            System.out.println("Token OK!!");
            
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(JWTValidator.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        } catch (InvalidJwtSignatureException sig) {
            System.out.println("Invalid Signature!!");
            System.out.println(sig.getMessage());
            return false;
        } catch (InvalidJwtException claim) {
            System.out.println("Invalid Token!!");
            System.out.println(claim.getMessage());
            //claim.printStackTrace();
            return false;
        }
        return true;
    }

}
