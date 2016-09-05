package custom.wso2.carbon.identity.application.authenticator.persistantId;

import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SymcorSPAuthenticatorDAO {

    public int getPlatformInfo(String userName) throws SQLException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        int platformInfo = -1;

        try {
            prepStmt = connection.prepareStatement(SQLQueries.GET_PLATFORM_INFO);
            prepStmt.setString(1, userName);
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                platformInfo = resultSet.getInt(1);
            }
        } catch (SQLException e) {
            throw new SQLException("Error while reading platform info for user : " + userName);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return platformInfo;
    }

    public String getUsernameForNameID(String nameID) throws SQLException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String userName = null;
        ResultSet resultSet = null;

        try {
            prepStmt = connection.prepareStatement(SQLQueries.GET_USERNAME_FOR_NAMEID);
            prepStmt.setString(1, nameID);
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                userName = resultSet.getString(1);
            }
        } catch (SQLException e) {
            throw new SQLException("Failed reading username for NameID : " + nameID);
        }finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }

        return userName;
    }

    public void linkNameIDToUser (String userName, String nameID) throws SQLException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;

        try {
            prepStmt = connection.prepareStatement(SQLQueries.LINK_NAMEID_TO_USER);
            prepStmt.setString(1, nameID);
            prepStmt.setString(2, userName);
            prepStmt.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            throw new SQLException("Failed to update database with NameID : " + nameID + " for user : " + userName);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    public void removeNameID (String nameID) throws SQLException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(SQLQueries.REMOVE_NAMEID);
            prepStmt.setString(1, null);
            prepStmt.setString(2, nameID);
            prepStmt.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            throw new SQLException("Failed to remove NameID : " + nameID);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }
}
