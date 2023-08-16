package com.popularsafi.data;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class Conexion {
    // JDBC driver name and database URL
    static final String JDBC_DRIVER = "org.h2.Driver";
    static final String DB_URL = "jdbc:h2:~/test";

    //  Database credentials
    static final String USER = "sa";
    static final String PASS = "";

    public static Connection getConnection() {
        Connection conn = null;
        Statement stmt = null;
        try {
            Class.forName(JDBC_DRIVER);
            System.out.println("Connecting to database...");
            conn = DriverManager.getConnection(DB_URL,USER,PASS);
            return conn;
        } catch(SQLException se) {
            //Handle errors for JDBC
            se.printStackTrace();
            return null;
        } catch(Exception e) {
            //Handle errors for Class.forName
            e.printStackTrace();
            return null;
        }
    }

}
