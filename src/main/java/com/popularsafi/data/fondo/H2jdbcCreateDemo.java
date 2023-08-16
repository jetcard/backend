package com.popularsafi.data.fondo;
import com.popularsafi.data.Conexion;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class H2jdbcCreateDemo {

    public static void main(String[] args) {
        Connection conn = Conexion.getConnection();
        Statement stmt = null;
        try {
            stmt = conn.createStatement();
            String sql ="CREATE TABLE FONDO(C_FONDO_ID VARCHAR(255), D_FONDO  VARCHAR(255) )";
            stmt.executeUpdate(sql);
            System.out.println("Created table in given database...");

            // STEP 4: Clean-up environment
            stmt.close();
            conn.close();
        } catch(SQLException se) {
            //Handle errors for JDBC
            se.printStackTrace();
        } catch(Exception e) {
            //Handle errors for Class.forName
            e.printStackTrace();
        } finally {
            //finally block used to close resources
            try{
                if(stmt!=null) stmt.close();
            } catch(SQLException se2) {
            } // nothing we can do
            try {
                if(conn!=null) conn.close();
            } catch(SQLException se){
                se.printStackTrace();
            } //end finally try
        } //end try
        System.out.println("Goodbye!");
    }

}
