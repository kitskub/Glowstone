package net.glowstone.net.handler;

import net.glowstone.GlowServer;
import net.glowstone.entity.GlowPlayer;
import net.glowstone.net.Session;
import net.glowstone.net.message.login.EncryptionKeyResponseMessage;
import net.glowstone.util.SecurityUtils;
import org.bukkit.Bukkit;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.xml.bind.DatatypeConverter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.util.UUID;
import java.util.logging.Level;

public class EncryptionKeyResponseHandler extends MessageHandler<EncryptionKeyResponseMessage>{
    @Override
    public void handle(Session session, GlowPlayer player, EncryptionKeyResponseMessage message) {
        GlowServer.logger.log(Level.INFO, "Begin handle encryption response");


        final Cipher rsaCipher = SecurityUtils.generateRSACipher(Cipher.DECRYPT_MODE, session.getServer().getKeyPair().getPrivate());

        GlowServer.logger.log(Level.INFO, "Created cipher using private rsa key");
        GlowServer.logger.log(Level.INFO, "Shared secret: {0}, length {1}", new Object[] {message.getSharedSecret(), message.getSharedSecret().length});
        GlowServer.logger.log(Level.INFO, "Verify Token: {0}, length {1}", new Object[] {message.getVerifyToken(), message.getVerifyToken().length});

        //Decrypt the shared secret and verify token using our private key in an rsa cipher.
        final byte[] sharedSecret = rsaCipher.update(message.getSharedSecret());
        byte[] verifyToken = null;
        try {
            verifyToken = rsaCipher.doFinal(message.getVerifyToken());
        } catch (Exception ex) {
            GlowServer.logger.log(Level.INFO, "Cannot decrypt verify token: {0}", ex.getMessage());
        }

        if(!verifyToken.equals(session.getVerifyToken())) {
            session.disconnect("Invalid verify token.");
            return;
        }

        GlowServer.logger.log(Level.INFO, "Decrypted shared secret and verify token");

        //Create our hash to be used in the authentication post.
        final MessageDigest digest = SecurityUtils.generateSHA1MessageDigest();
        digest.update(session.getSessionId().getBytes());
        digest.update(sharedSecret);
        digest.update(session.getServer().getKeyPair().getPublic().getEncoded());

        final String hash = DatatypeConverter.printHexBinary(digest.digest());

        ClientAuthentication clientAuth = new ClientAuthentication(session.getVerifyUsername(), hash, session);
        new Thread(clientAuth).start();
    }

    private class ClientAuthentication implements Runnable {

        private final String baseURL = "https://sessionserver.mojang.com/session/minecraft/hasJoined";
        private final String username;
        private final String hash;
        private final String postURL;

        private final Session session;

        private ClientAuthentication(String username, String hash, Session session) {
            this.username = username;
            this.hash = hash;
            this.postURL = new StringBuilder(baseURL)
                    .append("?username=")
                    .append(username)
                    .append("&serverId=")
                    .append(hash).toString();
            this.session = session;
        }

        @Override
        public void run() {
            GlowServer.logger.log(Level.INFO, "ClientAuth started");

            URLConnection conn = null;
            String response = "";

            try {
                URL url = new URL(postURL);
                conn = url.openConnection();

                InputStream is = conn.getInputStream();
                JSONObject json = (JSONObject) new JSONParser().parse(new InputStreamReader(is));
                System.out.println(json.toJSONString());

                final String id = (String) json.get("id");

                session.getServer().getScheduler().runTask(null, new Runnable() {
                    @Override
                    public void run() {
                        UUID uuid;

                        try {
                            uuid = UUID.fromString(id);
                        } catch (IllegalArgumentException ex) {
                            GlowServer.logger.log(Level.SEVERE, "Returned authentication uuid invalid: {0}", ex.getMessage());
                            session.disconnect("Invalid UUID.");
                            return;
                        }

                        session.setPlayer(new GlowPlayer(session, username, uuid));
                    }
                });
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
