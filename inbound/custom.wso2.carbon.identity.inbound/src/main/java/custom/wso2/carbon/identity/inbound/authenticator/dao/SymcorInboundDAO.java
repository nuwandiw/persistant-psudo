package custom.wso2.carbon.identity.inbound.authenticator.dao;

import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SymcorInboundDAO {

    private static final String REMOVE_NAMEID = "UPDATE SSO_SP_USER SET SAML2_NAMEID_INFOKEY=? WHERE SAML2_NAMEID_INFOKEY=?";
    public static final String GET_USERNAME_FOR_NAMEID = "SELECT LOGIN_NAME FROM SSO_SP_USER WHERE SAML2_NAMEID_INFOKEY=?";

    public void removeNameID (String nameID) throws SQLException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(REMOVE_NAMEID);
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

    public String getUsernameForNameID(String nameID) throws SQLException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String userName = null;
        ResultSet resultSet = null;

        try {
            prepStmt = connection.prepareStatement(GET_USERNAME_FOR_NAMEID);
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
}
