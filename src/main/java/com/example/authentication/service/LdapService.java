package com.example.authentication.service;

import com.example.authentication.Pojo.AuthenticationRequest;
import com.example.authentication.Entity.SmsaUser;
import org.springframework.stereotype.Service;
import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.Hashtable;


@Service
public class LdapService {

    static String lHostName = "10.24.153.129";
    static String lDomainName = "icicibankltd.com";
    static String lPort = "389";
    static String lLDAPAppl = "ldap";

    static boolean domainStatus = false;

    public SmsaUser ldapAuthService(AuthenticationRequest request) throws NamingException {
        Hashtable<String, String> lEnv;

        try {
            lEnv = constructEnvironment(request.getUsername(), request.getPassword(), lDomainName, lHostName);
            System.out.println("Hi here before");
            LdapContext lLdapContext = new InitialLdapContext(lEnv, null);
            System.out.println("Constructing Protocol: " + lLdapContext.getEnvironment().get("java.naming.provider.url"));
            boolean isAuthenticated = authenticateLDAPUser(lLdapContext, request.getUsername(), request.getPassword(), lDomainName);

            if (isAuthenticated) {
                SmsaUser userDetails = findAccountByAccountName(lLdapContext, "DC=icicibankltd,DC=com", request.getUsername());
                return userDetails;
            } else {
                throw new NamingException("User authentication failed due to invalid credentials.");
            }
        } catch (CommunicationException cex) {
            System.err.println("Communication Exception: " + cex.getMessage());
            throw new NamingException("Unable to connect to the LDAP server. Please check the server address, port, and network connectivity.");
        } catch (AuthenticationException aex) {
            throw new NamingException("Invalid credentials provided. Authentication failed.");
        } catch (Exception ex) {
            throw new NamingException("An unexpected error occurred during LDAP authentication: " + ex.getMessage());
        }
    }
    public static SmsaUser findAccountByAccountName(DirContext ctx, String ldapSearchBase, String accountName)
            throws NamingException {
        System.out.println("Enter");
        String userId = null;
        SmsaUser userDetails = new SmsaUser();
        try {
            String searchFilter = "(&(objectClass=user)(sAMAccountName=" + accountName + "))";
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(2);
            NamingEnumeration results = ctx.search(ldapSearchBase, searchFilter, searchControls);
            while (results.hasMore()) {
                SearchResult sr = (SearchResult) results.next();
                if (userId == null) {
                    userId = sr.getNameInNamespace();
                }

                Attributes answer = sr.getAttributes();
                printAttrs(answer);
                Attributes attrs = sr.getAttributes();
                if (attrs != null) {
                    userDetails.setLoginId(getAttributeValue(attrs, "mailNickname"));
                    userDetails.setFirstName(getAttributeValue(attrs, "givenName") != null ? getAttributeValue(attrs, "givenName") : null); // Common Name
                   userDetails.setEmail(getAttributeValue(attrs, "mail") != null ? getAttributeValue(attrs, "mail") : null);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Execption while findAccountByAccountName");
        }
        System.out.println("Exiting with user id :" + userId);
        return userDetails;
    }
    static void printAttrs(Attributes attrs) {
        if (attrs == null) {
            System.out.println("No attributes");
        } else
            try {
                NamingEnumeration ae = attrs.getAll();
                while (ae.hasMore()) {
                    Attribute attr = (Attribute) ae.next();
                    System.out.println("attribute: " + attr.getID());

                    for (NamingEnumeration e = attr.getAll(); e.hasMore();) {
                        System.out.println("value: " + e.next());
                    }
                }
            } catch (NamingException e) {
                e.printStackTrace();
            }
    }

    private static String getAttributeValue(Attributes attrs, String attributeName) {
        try {
            Attribute attr = attrs.get(attributeName);
            if (attr != null) {
                return (String) attr.get();
            }
        } catch (NamingException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static Hashtable constructEnvironment(String pAdminUser, String pAdminPassword, String pDomainName, String lHostName) {
        Hashtable lEnv = new Hashtable();
        System.out.println("\n************************");
        System.out.println("      Constructing LDAP Environment !!!");
        System.out.println("************************\n");
        lEnv.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
        lEnv.put("java.naming.referral", "follow");
        lEnv.put("java.naming.security.principal", pAdminUser + "@" + pDomainName);
        System.out.println(" \nConstructing Environment through Configured LDAP ADMIN User : " + pAdminUser + "@" + pDomainName + "  !!!");
        lEnv.put("java.naming.security.credentials", pAdminPassword);
        lEnv.put("java.naming.security.authentication", "simple");

        lEnv.put("java.naming.provider.url", lLDAPAppl + "://" + lHostName + ":" + lPort);
        // (Optional) Connection timeout (in milliseconds)
        lEnv.put("com.sun.jndi.ldap.connect.timeout", "20000");

        // (Optional) Read timeout (in milliseconds)
        lEnv.put("com.sun.jndi.ldap.read.timeout", "20000");

        System.out.println("\n************************");
        System.out.println("\t\t\t\tLDAP Enviornment Constructed Successfully !!!!! ");
        System.out.println("************************\n");
        return lEnv;
    }

    public static boolean authenticateLDAPUser(LdapContext pLdapContext, String pUsername, String pPassword, String pDomainName) {
        System.out.println("\n************************");
        System.out.println("\tAuthenticating Users on LDAP Servers !!!!!");
        System.out.println("************************\n");
        try {
            boolean pDomainFlag = true;

            if (pDomainFlag) {
                if ((pDomainName != null) && (pDomainName.trim().length() != 0)) {
                    pUsername = pUsername + "@" + pDomainName.trim();
                    System.out.println("LDAP Normal User Name : " + pUsername);
                    System.out.println("Domain Name : " + pDomainName);
                } else {
                    pDomainName = lDomainName;
                    System.out.println("Domain Name : " + pDomainName);
                    pUsername = pUsername + ((pDomainName != null) ? "@" + pDomainName : "");
                }
            }

            pLdapContext.addToEnvironment("java.naming.security.principal", pUsername);
            System.out.println("Passing & Checking UserName on LDAP Server .......");
            pLdapContext.addToEnvironment("java.naming.security.credentials", pPassword);
            System.out.println("Passing & Checking Passwprd on LDAP Server .........");
            pLdapContext.reconnect(null);

            System.out.println("\n*******************************");
            System.out.println("     Authentication of User " + pUsername + " on LDAP Server Successfull !!!!!");
            System.out.println("*******************************\n");
            return true;
        } catch (AuthenticationException aex) {
            System.out.println("Invalid Credentials Supplied");
        } catch (NamingException nex) {
            System.out.println("Naming Exception Occured");
        } catch (Exception ex) {
            System.out.println("LDAP User Authentication Failed");
        }
        return false;
    }
}
