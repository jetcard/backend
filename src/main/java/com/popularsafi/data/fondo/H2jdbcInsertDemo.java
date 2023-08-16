package com.popularsafi.data.fondo;
import com.popularsafi.data.Conexion;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class H2jdbcInsertDemo {

    public static void main(String[] args) {
        Connection conn = null;
        Statement stmt = null;
        try{
            conn = Conexion.getConnection();
            stmt = conn.createStatement();
            String sql = "INSERT INTO FONDO " + "VALUES ('lo', 'jp')";

            stmt.executeUpdate(sql);
            sql = "INSERT INTO FONDO " + "VALUES ('Maaz', 'Fatma')";

            stmt.executeUpdate(sql);
            sql = "INSERT INTO FONDO " + "VALUES ('Zaid', 'Khan')";

            stmt.executeUpdate(sql);
            sql = "INSERT INTO FONDO " + "VALUES(Suit', 'Mitt')";

            stmt.executeUpdate(sql);
            System.out.println("Inserted records into the table...");

            // STEP 4: Clean-up environment
            stmt.close();
            conn.close();
        } catch(SQLException se) {
            // Handle errors for JDBC
            se.printStackTrace();
        } catch(Exception e) {
            // Handle errors for Class.forName
            e.printStackTrace();
        } finally {
            // finally block used to close resources
            try {
                if(stmt!=null) stmt.close();
            } catch(SQLException se2) {
            } // nothing we can do
            try {
                if(conn!=null) conn.close();
            } catch(SQLException se) {
                se.printStackTrace();
            } // end finally try
        } // end try
        System.out.println("Goodbye!");
    }
}