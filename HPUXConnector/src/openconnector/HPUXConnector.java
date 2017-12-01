/* (c) Copyright 2010 SailPoint Technologies, Inc., All Rights Reserved. */
/* (c) Copyright 2017 Gamatech Ltd. Hong Kong, Inc., All Rights Reserved. */

package openconnector;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.security.auth.login.AccountNotFoundException;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

/*
 * HP-UX Connector
 * 
 * Using Jsch jar package to implement SSH connection,
 * 
 * Account Supported Functions:
 * a. getSupportedObjectType()
 * b. getSupportedFeaturedFeatures(): replaced by application FeatureString
 * c. configure(): Not supported
 * d. setObjectType(): Default
 * e. close(): Do nothing
 * f. testConnection(): echo TestConnection
 * g. discoverSechema():
 * h. authenticate():
 * i. read(): cat /etc/passwd (/etc/shadow) or pwget
 * j. iterate(): Aggregation, cat /etc/passwd (/etc/shadow)
 * k. provision(): Not supported
 * l. create(): useradd
 * m. update(): usermod
 * n. delete(): userdel
 * o. unlock(): userdbset -d -u <username> auth_failures
 * p. enable(): passwd -d
 * q. (Trusted) enable(): /usr/lbin/modprpw -k
 * r. disable(): passwd -l
 * s. (Trusted) disable(): /usr/lbin/modprpw -e
 * t. setPassword(): passwd
 * 
 * Group Supported Functions:
 * a. read(): grget
 * b. iterate(): 
 * c. provision(): 
 * d. create(): 
 * e. update(): 
 * f. delete(): 
 * 
 */

public class HPUXConnector extends AbstractConnector {

	// //////////////////////////////////////////////////////////////////////////
	//
	// INNER CLASSES
	//
	// //////////////////////////////////////////////////////////////////////////

	/**
	 * An iterator that returns copies of the maps that are returned.
	 */
	private class CopyIterator implements Iterator<Map<String, Object>> {

		private Iterator<Map<String, Object>> it;

		public CopyIterator(Iterator<Map<String, Object>> it) {
			this.it = it;
		}

		@Override
		public boolean hasNext() {
			return this.it.hasNext();
		}

		@Override
		public Map<String, Object> next() {
			return copy(this.it.next());
		}

		@Override
		public void remove() {
			this.it.remove();
		}
	}

	// //////////////////////////////////////////////////////////////////////////
	//
	// CONSTANTS
	//
	// //////////////////////////////////////////////////////////////////////////

	public static final String ATTR_USERNAME = "username";
	public static final String ATTR_UID = "uid";
	public static final String ATTR_GID = "primgrp";
	public static final String ATTR_COMMENT = "comment";
	public static final String ATTR_HOME = "home";
	public static final String ATTR_GROUPS = "groups";

	public static final String ATTR_PWDLASTCHG = "pwdlastchg";
	public static final String ATTR_PWDMIN = "pwdmin";
	public static final String ATTR_PWDMAX = "pwdmax";
	public static final String ATTR_PWDWARN = "pwdwarn";
	public static final String ATTR_INACTIVE = "inactive";

	public static final String ATTR_DISABLED = "IIQDisabled";
	public static final String ATTR_LOCKED = "IIQLocked";
	public static final String ATTR_PASSWORD = "HPUXConnector.password";
	public static final String ATTR_PASSWORD_OPTIONS = "HPUXConnector.passwordOptions";
	public static final String ATTR_PASSWORD_HISTORY = "HPUXConnector.passwordHistory";

	public static final String GROUP_ATTR_NAME = "name";
	public static final String GROUP_ATTR_DESCRIPTION = "groupid";

	public static ArrayList<String> passwdDB = new ArrayList<String>();
	public static ArrayList<String> shadowDB = new ArrayList<String>();

	// //////////////////////////////////////////////////////////////////////////
	//
	// SERVER Variables
	//
	// //////////////////////////////////////////////////////////////////////////

	public static String idmuser_username;
	public static String idmuser_password;
	public static String host_ip;
	public static int ssh_port;
	public static boolean isSudoer;
	public static Session session;
	public static boolean hasShadowFile;
	public static boolean isTrusted;
	public static int sshLoginTimeout;

	// //////////////////////////////////////////////////////////////////////////
	//
	// STATIC FIELDS
	//
	// //////////////////////////////////////////////////////////////////////////

	private static Map<String, Map<String, Object>> accounts = new HashMap<String, Map<String, Object>>();
	private static Map<String, Map<String, Object>> groups = new HashMap<String, Map<String, Object>>();

	// //////////////////////////////////////////////////////////////////////////
	//
	// Support Functions
	//
	// //////////////////////////////////////////////////////////////////////////

	/**
	 * Print all objects in memory to System.out.
	 * 
	 */
	public static void dump() {
		System.out.println(accounts);
		System.out.println(groups);
	}

	/**
	 * Initial HPUXConnector
	 * 
	 * @version - HPUXConnector 1.0.0
	 */
	public void init() {
		String funcName = "init()";
		enter(funcName);
		exit(funcName);
	}

	/**
	 * Enter method is used to start the application method.
	 * 
	 * @version - ConnectorFactory 6.4.
	 *
	 */
	private void enter(String functionName) {
		if (log.isDebugEnabled())
			log.debug("Entering " + functionName + " ...");
	}

	/**
	 * Exit method is used to get out of the application method.
	 * 
	 * @version - ConnectorFactory 6.4.
	 *
	 */
	private void exit(String functionName) {

		if (log.isDebugEnabled())
			log.debug("Exitting " + functionName + " ...");
	}

	/**
	 * Read application xml configuration into global variables
	 * 
	 * @version - HPUXConnector 1.0.0
	 */
	private void configure() {
		String funcName = "configure()";
		enter(funcName);
		// System.out.println(config.getConfig());
		if (config.getConfig().containsKey("SudoUser")) {
			idmuser_username = config.getString("SudoUser");
		} else {
			// idmuser_username = "usert01";
		}
		if (config.getConfig().containsKey("SudoUserPassword")) {
			idmuser_password = config.getString("SudoUserPassword");
		} else {
			// idmuser_password = "password";
		}
		if (config.getConfig().containsKey("host")) {
			host_ip = config.getString("host");
		} else {
			// host_ip = "192.168.232.129";
		}
		if (config.getConfig().containsKey("SshPort")) {
			ssh_port = Integer.parseInt(config.getString("SshPort"));
		} else {
			ssh_port = 22;
		}
		if (config.getConfig().containsKey("IsSudoUser")) {
			isSudoer = config.getBoolean("IsSudoUser");
		} else {
			isSudoer = false;
		}
		if (config.getConfig().containsKey("hasShadowFile")) {
			hasShadowFile = config.getBoolean("hasShadowFile");
		} else {
			hasShadowFile = false;
		}
		if (config.getConfig().containsKey("IsTrusted")) {
			isTrusted = config.getBoolean("IsTrusted");
		} else {
			isTrusted = false;
		}
		if (config.getConfig().containsKey("SshLoginTimeout")) {
			sshLoginTimeout = Integer.parseInt(config.getString("sshLoginTimeout"));
		} else {
			sshLoginTimeout = 1000;
		}
		exit(funcName);
	}

	/**
	 * SSH send command sh, open shell, NOT WORK current
	 * 
	 * @version - HPUXConnector 1.0.0
	 */
	private void sshShellStart() {
		String funcName = "sshShellStart()";
		enter(funcName);
		String executeCommand = "sh";
		String retPrompt;
		retPrompt = sshCommandExecute(executeCommand);
		if (log.isDebugEnabled())
			System.out.println(retPrompt);
		exit(funcName);
	}

	/**
	 * Use JSch library to establish SSH connection Dev: Disable Hostkey
	 * Checking....
	 * 
	 * @version - HPUXConnector 1.0.0
	 */
	public void sshLogin() throws Exception {
		String funcName = "sshLogin()";
		enter(funcName);
		configure();
		try {
			JSch jsch = new JSch();

			session = jsch.getSession(idmuser_username, host_ip, ssh_port);
			session.setPassword(idmuser_password);
			/*
			 * Disable Hostkey for testing only
			 */
			java.util.Properties properties = new java.util.Properties();
			properties.put("StrictHostKeyChecking", "no");
			session.setConfig(properties);
			session.connect(sshLoginTimeout);

		} catch (JSchException e) {
			if (log.isDebugEnabled())
				log.error("Error for SSH TestConnection ", e);
			throw new ConnectorException("SSH Test Connection failed with message : " + e.getMessage() + ".  Please check the connection details.");
		}
		exit(funcName);
	}

	/**
	 * SSH disconnect
	 * 
	 * @throws Exception
	 * @version - HPUXConnector 1.0.0
	 */
	public void sshLogout() throws Exception {
		String funcName = "sshLogout()";
		enter(funcName);
		if (session != null)
			session.disconnect();
		exit(funcName);
	}

	/**
	 * Send command with ssh channel If isSudoer is enabled, add sudo to command
	 * prefix
	 * 
	 * @param command
	 * @return prompt
	 * @version - HPUXConnector 1.0.0
	 * 
	 */
	public String sshCommandExecute(String command) {
		String funcName = "sshCommandExecute()";
		enter(funcName);
		// Add sudo command if needed
		if (isSudoer)
			command = "sudo -S -p %SAILPOINTSUDO " + command;
		StringBuilder outputBuffer = new StringBuilder();
		try {
			Channel channel = session.openChannel("exec");
			if (log.isDebugEnabled())
				System.out.println("HPUX Connector Execute Command:" + command);
			((ChannelExec) channel).setCommand(command);
			InputStream commandOutput = channel.getInputStream();
			((ChannelExec) channel).setPty(true);
			channel.connect();
			if (isSudoer) {
				OutputStream out = channel.getOutputStream();
				((ChannelExec) channel).setErrStream(System.err);

				out.write((idmuser_password + "\n").getBytes());
				out.flush();
			}

			int readByte = commandOutput.read();
			while (readByte != 0xffffffff) {
				outputBuffer.append((char) readByte);
				readByte = commandOutput.read();
			}
			channel.disconnect();
		} catch (IOException ioX) {
			System.out.println(ioX.getMessage());
			return null;
		} catch (JSchException jschX) {
			System.out.println(jschX.getMessage());
			return null;
		}
		String output = outputBuffer.toString();
		if (isSudoer) {
			// Remove first line
			output = output.substring(output.indexOf('\n') + 1);
			// Remove second line
			output = output.substring(output.indexOf('\n') + 1);
		}
		output = output.trim();
		System.out.println("Return Prompt Result:" + output);
		exit(funcName);
		return output;
	}

	/**
	 * Used for interactive setPassword
	 * 
	 * @param command the command to be executed from configuration xml
	 * @param newPassword 
	 * @param currentPassword
	 * @return void
	 * @version - HPUXConnector 1.0.0
	 * 
	 */
	@SuppressWarnings("unchecked")
	public void sshInteractiveSetPassword(String command, String newPassword, String currentPassword) {
		String funcName = "sshInteractiveSetPassword()";
		enter(funcName);
		// Add sudo command if needed
		if (isSudoer)
			command = "sudo -p %SAILPOINTSUDO " + command;

		try {
			Channel channel = session.openChannel("exec");
			if (log.isDebugEnabled())
				System.out.println("HPUX Connector Execute Command:" + command);
			((ChannelExec) channel).setCommand(command);
			InputStream in = channel.getInputStream();
			((ChannelExec) channel).setPty(true);

			channel.connect();
			OutputStream out = channel.getOutputStream();
			((ChannelExec) channel).setErrStream(System.err);

			String prompt;
			byte[] tmp = new byte[1024];
			while (true) {
				while (in.available() > 0) {
					int i = in.read(tmp, 0, 1024);
					if (i < 0)
						break;
					// System.out.print(new String(tmp, 0, i));
					prompt = new String(tmp);
					String lines[] = prompt.split("\\r?\\n");
					prompt = lines[lines.length - 1];
					prompt = prompt.trim();
					if (log.isDebugEnabled())
						System.out.println(prompt);
					//
					// Get sudo passowrd prompt
					//
					if ("%SAILPOINTSUDO".equals(prompt)) {
						out.write((idmuser_password + "\n").getBytes());
						out.flush();
						continue;
					}
					//
					// Get Passwd Success Prompt
					//
					ArrayList<String> passwdSuccessList;
					if (config.getConfig().containsKey("PasswdSuccess")) {
						passwdSuccessList = (ArrayList<String>) config.getAttribute("PasswdSuccess");
					} else {
						passwdSuccessList = new ArrayList<String>();
						passwdSuccessList.add("passwd: all authentication tokens updated successfully.");
					}
					if (passwdSuccessList.contains(prompt)) {
						channel.disconnect();
						break;
					}
					//
					// Get Passwd Prompts
					//
					if (config.getConfig().containsKey("PasswdPrompts")) {
						Map<String, String> passwdPromptsMap = (Map<String, String>) config.getAttribute("PasswdPrompts");
						Iterator it = passwdPromptsMap.entrySet().iterator();
						while (it.hasNext()) {
							Map.Entry pair = (Map.Entry) it.next();
							String passwdPrompt = (String) pair.getKey();
							String promptType = (String) pair.getValue();
							// if (log.isDebugEnabled())
							// System.out.println(passwdPrompt + " = " +
							// promptType);
							if (prompt.equalsIgnoreCase(passwdPrompt)) {
								if ("CurrentPassword".equals(promptType)) {
									out.write((currentPassword + "\n").getBytes());
									out.flush();
								} else if ("NewPassword".equals(promptType)) {
									out.write((newPassword + "\n").getBytes());
									out.flush();
								}
								break;
							}
						}
					} else {
						if (prompt.equalsIgnoreCase("Old password:")) {
							out.write((currentPassword + "\n").getBytes());
							out.flush();
						}
						if (prompt.equalsIgnoreCase("New password:")) {
							out.write((newPassword + "\n").getBytes());
							out.flush();
						}
						if (prompt.equalsIgnoreCase("Re-enter new password:")) {
							out.write((newPassword + "\n").getBytes());
							out.flush();
						}
					}
				}
				if (channel.isClosed()) {
					if (log.isDebugEnabled())
						System.out.println("SSH Channel Closed, exit-status: " + channel.getExitStatus());
					break;
				}
				try {
					Thread.sleep(1000);
				} catch (Exception ee) {
				}
			}
		} catch (IOException ioX) {
			System.out.println(ioX.getMessage());
		} catch (JSchException jschX) {
			System.out.println(jschX.getMessage());
		}
		exit(funcName);
	}

	/**
	 * SSH send command echo $?, Get execution status
	 * 
	 * @return status
	 * @version - HPUXConnector 1.0.0
	 */
	private int getShellExecutionStatus() {
		String funcName = "getShellExecutionStatus()";
		enter(funcName);
		int status = 0;
		String executeCommand = "echo $?";
		String retPrompt;
		retPrompt = sshCommandExecute(executeCommand);
		if (log.isDebugEnabled())
			System.out.println(retPrompt);
		status = Integer.valueOf(retPrompt);
		exit(funcName);
		return status;
	}

	/**
	 * Set Shell Prompt from xml configuration if set, default is 'PS1='SAILPOINT>'
	 * 
	 * @version - HPUXConnector 1.0.0
	 */
	private void setShellPrompt() {
		String funcName = "getShellExecutionStatus";
		enter(funcName);
		String executeCommand;
		if (config.getConfig().containsKey("SetPrompt")) {
			executeCommand = config.getString("SetPrompt");
		} else {
			executeCommand = "PS1=\'SAILPOINT>\'";
		}
		String retPrompt;
		retPrompt = sshCommandExecute(executeCommand);
		if (log.isDebugEnabled())
			System.out.println(retPrompt);
		exit(funcName);
	}

	/**
	 * Get /etc/shadow file format from application configuration
	 * 
	 * @version - HPUXConnector 1.0.0
	 */
	@SuppressWarnings("unchecked")
	private void getShadowDBFormat() {
		String funcName = "getShadowDBFormat()";
		enter(funcName);
		// initial shadowDB
		if (config.getConfig().containsKey("ShadowDBFormat")) {
			shadowDB = (ArrayList<String>) config.getAttribute("ShadowDBFormat");
		} else {
			if (log.isDebugEnabled())
				log.debug("No Shadow DB found, using default...");
			shadowDB = new ArrayList<String>();
			shadowDB.add("username");
			shadowDB.add("encryptedPwd");
			shadowDB.add("pwdlastchg");
			shadowDB.add("pwdmin");
			shadowDB.add("pwdmax");
			shadowDB.add("pwdwarn");
			shadowDB.add("inactive");
			shadowDB.add("expiration");
			shadowDB.add("reserved");
		}
		exit(funcName);
	}

	/**
	 * Get /etc/passwd file format from application configuration
	 * 
	 * @version - HPUXConnector 1.0.0
	 */
	@SuppressWarnings("unchecked")
	private void getPasswdDBFormat() {
		String funcName = "getPasswdDBFormat()";
		enter(funcName);
		// initial passwdDB
		if (config.getConfig().containsKey("PwdDBFormat")) {
			passwdDB = (ArrayList<String>) config.getAttribute("PwdDBFormat");
		} else {
			if (log.isDebugEnabled())
				log.debug("No Passwd DB found, using default...");
			passwdDB = new ArrayList<String>();
			passwdDB.add("username");
			passwdDB.add("password");
			passwdDB.add("uid");
			passwdDB.add("primgrp");
			passwdDB.add("comment");
			passwdDB.add("home");
			passwdDB.add("shell");
		}

		exit(funcName);
	}

	/**
	 * Get user last login info last(1): Reference:
	 * http://nixdoc.net/man-pages/HP-UX/last.1.html
	 * 
	 * @param nativeIdentifier account id on the end point system
	 * @return lastLogin time in string format 
	 * @version - HPUXConnector 1.0.0
	 */
	private String getLastLoginTimeInformation(String nativeIdentifier) {
		String funcName = "getLastLoginTimeInformation()";
		enter(funcName);
		String executeCommand, retPrompt, lastLogin;
		lastLogin = null;

		String getLastLoginTimeInformationCommand;
		if (config.getConfig().containsKey("lastlogin.account")) {
			getLastLoginTimeInformationCommand = config.getString("lastlogin.account");
		} else {
			if (log.isDebugEnabled())
				log.debug("Can't found lastlogin.account command, using default:last ...");
			getLastLoginTimeInformationCommand = "last";
		}

		executeCommand = getLastLoginTimeInformationCommand + " " + nativeIdentifier;
		retPrompt = sshCommandExecute(executeCommand);
		if (retPrompt != null)
			lastLogin = retPrompt.split("\\s+")[1];

		exit(funcName);
		return lastLogin;
	}

	/**
	 * HP-UX using command userstat -u to indicate account status Mode
	 * reference: userstat(1M)
	 * http://docstore.mik.ua/manuals/hp-ux/en/B2355-60130/userstat.1M.html
	 * 
	 * @param nativeIdentifier account id on the end point system
	 * @return Account_Status either Disabled/Enabled/Locked
	 * @version - HPUXConnector 1.0.0
	 */
	private String getAccountActiveStatus(String nativeIdentifier) {
		String funcName = "getAccountActiveStatus()";
		enter(funcName);
		String getAccountActiveStatusCommand, executeCommand, retPrompt, result, status;
		result = "Enabled";

		if (config.getConfig().containsKey("aggregation.lockstatus")) {
			getAccountActiveStatusCommand = config.getString("aggregation.lockstatus");
		} else {
			if (log.isDebugEnabled())
				log.debug("Can't found aggregation.lockstatus command, using default:echo TestConnection...");
			getAccountActiveStatusCommand = "userstat -u ";
		}

		executeCommand = getAccountActiveStatusCommand + " " + nativeIdentifier;
		retPrompt = sshCommandExecute(executeCommand);
		status = retPrompt.split("\\s+")[1];
		if (status != null) {
			if (status.equals("admlock")) {
				result = "Disabled";
			}
			if (status.contains("expacct")) {
				result = "Locked";
			}
			if (status.contains("exppw")) {
				result = "Locked";
			}
			if (status.contains("inactive")) {
				result = "Locked";
			}
			if (status.contains("maxtries")) {
				result = "Locked";
			}
			if (status.contains("nullpw")) {
				result = "Locked";
			}
			if (status.contains("tod")) {
				result = "Locked";
			}
			if (status.equals("LK")) {
				result = "Disabled";
			}
		}
		exit(funcName);
		return result;
	}

	/**
	 * Check if username is exists HP-UX using command pwget -n to retrieve data
	 * from passwd DB reference: pwget(1M)
	 * http://docstore.mik.ua/manuals/hp-ux/en/B2355-60130/pwget.1.html
	 * 
	 * @param nativeIdentifier account id on the end point system
	 * @version - HPUXConnector 1.0.0
	 */
	private boolean isAccountExists(String nativeIdentifier) throws Exception {
		String funcName = "isAccountExists()";
		enter(funcName);
		boolean isExists = false;
		// Before calling this function SSH session should be established
		// Build Command
		String isAccountExistsCommand = "";
		if (config.getConfig().containsKey("isexists.account")) {
			isAccountExistsCommand = config.getString("isexists.account");
		} else {
			if (log.isDebugEnabled())
				log.debug("Can't found isexists.account command, using default:pwget -n...");
			isAccountExistsCommand = "pwget -n";
		}
		String executeCommand = isAccountExistsCommand + " " + nativeIdentifier;
		String returnPrompt = sshCommandExecute(executeCommand);
		if (returnPrompt != null && returnPrompt.contains(nativeIdentifier)) {
			if (log.isDebugEnabled())
				System.out.println(returnPrompt);
			isExists = true;
		}
		int status = getShellExecutionStatus();
		// These commands(pwget) return 0 upon success, 1 when a specific search fails, and 2 upon error.
		if (status == 2) {
			throw new Exception("isAccountExists() Command unexcepted error:" + executeCommand);
		}
		exit(funcName);
		return isExists;
	}

	/**
	 * Return command parameter value inside appliction xml
	 * 
	 * @param command the executed command
	 * @param attr normally exists prompt or flag parameters
	 * @param key the key value for exists/flags map
	 * @version - HPUXConnector 1.0.0
	 */
	private String getAttributeMapValue(String command, String attr, String key) {
		String option = null;
		if (config.getConfig().containsKey(command)) {
			@SuppressWarnings("unchecked")
			Map<String, Map<String, String>> map1 = (Map<String, Map<String, String>>) config.getAttribute(command);
			Map<String, String> map2 = map1.get(attr);
			option = map2.get(key);
		} else {
			if (log.isDebugEnabled())
				System.out.println("Can't find option flag for:" + command + "->" + attr + "->" + key);
		}
		return option;
	}
	
	/**
	 * Print all objects in memory to System.out.
	 * 
	 */
	private static String digitsMapping(char digit) {
		int temp;
		int ascii;
		String digitStr = Character.toString(digit);
		
		if(digitStr.equals(".")) return "0";
		else if(digitStr.equals("/")) return "1";
		else if(digitStr.matches("[0-9]")) {
			temp = Integer.parseInt(digitStr);
			temp += 2;
			return String.valueOf(temp);
		}
		else if(digitStr.matches("[A-Z]")) {
			ascii = (int) digit;
			temp = ascii - 53;
			return String.valueOf(temp);
		}
		else if(digitStr.matches("[a-z]")) {
			ascii = (int) digit;
			temp = ascii - 59;
			return String.valueOf(temp);
		}
		else return "0";
	}

	// //////////////////////////////////////////////////////////////////////////
	//
	// CONSTRUCTORS
	//
	// //////////////////////////////////////////////////////////////////////////

	/**
	 * Default constructor.
	 */
	public HPUXConnector() {
		super();
	}

	/**
	 * Constructor for an account HPUXConnector.
	 * 
	 * @param config
	 *            The ConnectorConfig to use.
	 * @param log
	 *            The Log to use.
	 */
	public HPUXConnector(ConnectorConfig config, Log log) {
		super(config, log);
	}

	// //////////////////////////////////////////////////////////////////////////
	//
	// LIFECYCLE
	//
	// //////////////////////////////////////////////////////////////////////////

	/**
	 * Test if ssh connection is success
	 * 
	 * @return connRes true for success false for failed
	 * @throws Exception
	 * @version - HPUXConnector 1.0.0
	 */
	public boolean sshTestConnection() throws Exception {
		String funcName = "sshTestConnection";
		enter(funcName);
		boolean connRes = false;
		sshLogin();
		if (session != null) {
			// Build Command
			String executeCommand = "";
			if (config.getConfig().containsKey("testconnection")) {
				executeCommand = config.getString("testconnection");
			} else {
				if (log.isDebugEnabled())
					log.debug("Can't found testconnection command, using default:echo TestConnection...");
				executeCommand = "echo TestConnection";
			}
			String returnPrompt = sshCommandExecute("echo TestConnection");
			System.out.println("sshTestConnection testConnPrompt:" + returnPrompt);

			// Build return prompt check
			String testConnPrompt = getAttributeMapValue(executeCommand, "exitsts", "Success");
			if (testConnPrompt == null)
				testConnPrompt = "TestConnection";

			if (testConnPrompt.equals(returnPrompt)) {
				connRes = true;
			} else {
				connRes = false;
			}
		}
		exit(funcName);
		return connRes;
	}

	/**
	 * No resources to close.
	 */
	@Override
	public void close() {
		String funcName = "close";
		enter(funcName);
		exit(funcName);
	}

	/**
	 * Using ssh to test connection
	 * 
	 * @version - HPUXConnector 1.0.0
	 */
	@Override
	public void testConnection() {
		String funcName = "testConnection()";
		enter(funcName);
		try {
			if (sshTestConnection()) {
				System.out.println("Connect Success!");
			} else {
				System.out.println("Connect Failed!");
			}
		} catch (Exception e) {
			if (log.isDebugEnabled())
				log.error("Error for TestConnection ", e);
			throw new ConnectorException("Test Connection failed with message : " + e.getMessage() + ".  Please check the connection details.");
		}
		exit(funcName);
	}

	/**
	 * NOTE: This method is not currently used by IdentityIQ; instead, the
	 * application object's FeaturesString is used to determine the connector's
	 * supported features.
	 */
	@Override
	public List<Feature> getSupportedFeatures(String objectType) {
		return Arrays.asList(Feature.values());
	}

	/**
	 * Support account operation only Disable group operation
	 * 
	 * @version - HPUXConnector 1.0.0
	 */
	@Override
	public List<String> getSupportedObjectTypes() {
		List<String> types = super.getSupportedObjectTypes();
		types.add(OBJECT_TYPE_ACCOUNT);
		// types.add(OBJECT_TYPE_GROUP);
		return types;
	}

	// //////////////////////////////////////////////////////////////////////////
	//
	// BASIC CRUD
	//
	// //////////////////////////////////////////////////////////////////////////

	/**
	 * Return the Map that has the objects for the currently configured object
	 * type. This maps native identifier to the resource object with that
	 * identifier.
	 */
	private Map<String, Map<String, Object>> getObjectsMap() throws ConnectorException {

		if (OBJECT_TYPE_ACCOUNT.equals(this.objectType)) {
			return accounts;
		} else if (OBJECT_TYPE_GROUP.equals(this.objectType)) {
			return groups;
		}
		throw new ConnectorException("Unhandled object type: " + this.objectType);
	}

	/**
	 * LCM - Create Account Additional options will be implement into one
	 * command
	 * 
	 * @param nativeIdentifier account id on the end point system
	 * @param items parameters along with create account commands
	 * @return result provisioning result and exceptions
	 * @version - HPUXConnector 1.0.0
	 */
	@Override
	public Result create(String nativeIdentifier, List<Item> items) throws ConnectorException, ObjectAlreadyExistsException {
		String funcName = "create()";
		enter(funcName);

		Result result = new Result();

		System.out.println("Create items:" + items.toString());
		try {
			sshLogin();
			if (session != null) {
				if (OBJECT_TYPE_ACCOUNT.equals(this.objectType)) {
					//
					// Check if Account Already Exists
					//
					if (isAccountExists(nativeIdentifier)) {
						throw new Exception(nativeIdentifier + " already exists in the system");
					}
					if (log.isDebugEnabled())
						log.debug("Create Account NativeIdentitifer:" + nativeIdentifier);
					// setShellPrompt();
					//
					// Build Command
					//
					String createCommand = "";
					if (config.getConfig().containsKey("create.account")) {
						createCommand = config.getString("create.account");
					} else {
						if (log.isDebugEnabled())
							log.debug("Can't found create.account command, using default:useradd...");
						createCommand = "useradd";
					}
					String executeCommand = createCommand;
					//
					// Add command flags, incomplete
					//
					System.out.println("------------------ Create Account Options ----------------");
					if (items != null) {
						for (Item item : items) {
							String name = item.getName();
							Object value = item.getValue();
							Item.Operation op = item.getOperation();
							switch (op) {
							case Add:
								break;
							case Remove:
								break;
							case Set: {
								if (log.isDebugEnabled())
									System.out.println("Create Account item:" + name + "---->" + value);
								String flag = getAttributeMapValue(createCommand, "flags", name);
								if (flag != null)
									executeCommand = executeCommand + " " + flag + " " + value;
							}
								break;
							default:
								throw new IllegalArgumentException("Unknown operation: " + op);
							}
						}
					}
					System.out.println("----------------------------------------------------------");
					//
					// Add nativeIdentifier
					//
					executeCommand = executeCommand + " " + nativeIdentifier;
					sshCommandExecute(executeCommand);
					//
					// Get execution result status
					//
					int status = getShellExecutionStatus();
					if (status != 0) {
						String errorMsg = getAttributeMapValue(createCommand, "exitsts", String.valueOf(status));
						if (errorMsg == null)
							errorMsg = "Create account encountered unexcepted error...";
						result.setStatus(Result.Status.Failed);
						result.add(errorMsg);
					} else {
						result.setStatus(Result.Status.Committed);
					}
					//
					// Set up Password
					//
					Map<String, Object> options = new HashMap<String, Object>();
					String newPassword = null;
					if (items != null) {
						for (Item item : items) {
							String name = item.getName();
							Object value = item.getValue();
							Item.Operation op = item.getOperation();
							if (op == Item.Operation.Set) {
								if ("password".equals(name))
									newPassword = (String) value;
								else
									options.put(name, value);
							}

						}
					}
					// Get current password
					if (newPassword != null) {
						Result setPasswordResult = setPassword(nativeIdentifier, newPassword, null, null, options);
						result.add(setPasswordResult.getMessages());
					}
				} else if (OBJECT_TYPE_GROUP.equals(this.objectType)) {
					if (log.isDebugEnabled())
						log.debug("Not Support Create Group Operation");
					result.setStatus(Result.Status.Committed);
				}
			} else {
				if (log.isDebugEnabled())
					log.debug("SSH session is LOST!!!");
				result.setStatus(Result.Status.Failed);
				result.add("SSH session is LOST!!!");
			}
			sshLogout();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.out.println(e.getMessage());
			e.printStackTrace();
		}

		Map<String, Object> object = new HashMap<String, Object>();
		object.put(getIdentityAttribute(), nativeIdentifier);
		if (items != null) {
			for (Item item : items)
				object.put(item.getName(), item.getValue());
		}
		getObjectsMap().put(nativeIdentifier, object);
		result.setObject(object);

		exit(funcName);
		return result;
	}

	/**
	 * LCM - Read Account
	 * 
	 * @version - HPUXConnector 1.0.0
	 */
	@Override
	public Map<String, Object> read(String nativeIdentifier) throws ConnectorException, IllegalArgumentException {
		return read(nativeIdentifier, true);
	}

	/**
	 * LCM - Read Account
	 * 
	 * @param nativeIdentifier account id on the end point system
	 * @param unused
	 * @return Resource Object in Map format
	 * @version - HPUXConnector 1.0.0
	 */
	private Map<String, Object> read(String nativeIdentifier, boolean forUpdate) throws ConnectorException, IllegalArgumentException {
		String funcName = "read()";
		enter(funcName);

		if (null == nativeIdentifier) {
			throw new IllegalArgumentException("nativeIdentitifier is required");
		}

		Map<String, Object> obj = getObjectsMap().get(nativeIdentifier);
		Map<String, Object> updateObj = new HashMap<String, Object>();
		try {
			getPasswdDBFormat();
			getShadowDBFormat();
			String accStatus = "Enabled";
			String retPrompt;
			sshLogin();
			if (session != null) {
				if (OBJECT_TYPE_ACCOUNT.equals(this.objectType)) {
					if (!isAccountExists(nativeIdentifier)) {
						throw new AccountNotFoundException(nativeIdentifier + " not exists in the system");
					}
					// sshShellStart();
					int status = 0;
					// setShellPrompt();
					String executeCommand = "";
					//
					// Read passwd file
					//
					executeCommand = executeCommand + "cat /etc/passwd ";
					//
					// Read shadow file if exists
					//
					if (hasShadowFile)
						executeCommand = executeCommand + "/etc/shadow ";
					executeCommand = executeCommand + "| awk -F ':' '{if($1 == \"" + nativeIdentifier + "\") print}'";
					retPrompt = sshCommandExecute(executeCommand);
					if (log.isDebugEnabled())
						log.debug(retPrompt);
					status = getShellExecutionStatus();
					if (status != 0)
						System.out.println("[ERROR] Shell Exeucte Command: " + executeCommand + ", Failed, Status = " + status);
					/*
					 * Execute command: (sudo) id -g -n <nativeIdentifier>
					 */
					executeCommand = "id -g -n " + nativeIdentifier;
					retPrompt = sshCommandExecute(executeCommand);
					if (log.isDebugEnabled())
						log.debug(retPrompt);
					status = 0;
					status = getShellExecutionStatus();
					if (status == 1)
						System.out.println("[ERROR] id: User not found or invalid options or invalid combination of options.");
					else if (status == 2)
						System.out.println("[ERROR] id: The -P option is given when PRM is not supported or configured.");
					
					
					/*
					 *  Here we differentiate system with shadow utility and without. 
					 *  System with shadow utility will store the password information in the shadow file.
					 *  System without shadow, password information will store in the passwd password field with 
					 *  certain format. 
					 *  
					 *  The encrypted password consists of 13 characters chosen from a 64-character set of "digits" 
					 *  described below, Login can be prevented by entering in the password field a character 
					 *  that is not part of the set of digits (such as *)
					 *  
					 *  The characters used to represent "digits" are . for 0, / for 1, 0 through 9 for 2 
					 *  through 11, A through Z for 12 through 37, and a through z for 38 through 63.
					 *  
					 *  Password aging is put in effect for a particular user if his encrypted password in 
					 *  the password file is followed by a comma and a non-null string of characters from the 
					 *  above alphabet. (Such a string must be introduced in the first instance by a superuser.) 
					 *  This string defines the "age" needed to implement password aging.
					 *  
					 *  UNIX keeps internal time stamps in a format with a base date of Thursday January 1, 1970. 
					 *  Because of this, passwd considers the beginning of a week to be 00:00 GMT Thursday.
					 *  
					 *  The first character of the age, M, denotes the maximum number of weeks for which a password 
					 *  is valid. A user who attempts to login after his password has expired is forced to supply a 
					 *  new one. The next character, m, denotes the minimum period in weeks that must expire before 
					 *  the password can be changed. The remaining two characters define the week when the password 
					 *  was last changed (a null string is equivalent to zero). M and m have numerical values in the 
					 *  range 0 through 63 that correspond to the 64-character set of "digits" shown above.
					 *  
					 *  If m = M = 0 (derived from the string . or ..), the user is forced to change his password next 
					 *  time he logs in (and the "age" disappears from his entry in the password file). If m > M 
					 *  (signified, for example, by the string ./), then only a superuser (not the user) can change the 
					 *  password. Not allowing the user to ever change the password is discouraged.
					 */
					
					
					
					// Normal case
					if(hasShadowFile) {
						/*
						 * Retrieve data from passwd file
						 */
						executeCommand = "cat /etc/passwd | awk -F ':' '{if($1 == \"" + nativeIdentifier + "\") print}'";
						retPrompt = sshCommandExecute(executeCommand);
						String[] passwdDBAcc = retPrompt.split(":", -1);
						String attribute;
						String attrVal;
						for (int i = 0; i < passwdDB.size(); i++) {
							if (i != 1) {
								attribute = passwdDB.get(i);
								if (log.isDebugEnabled())
									log.debug("Current attribute=" + attribute);
								attrVal = passwdDBAcc[i];

								if (attrVal != null && log.isDebugEnabled())
									log.debug("Found in Passwd, value:" + attrVal);

								if (attrVal != null)
									updateObj.put(attribute, attrVal);
							}
						}
						status = 0;
						status = getShellExecutionStatus();
						if (status != 0)
							System.out.println("[ERROR] Shell Exeucte Command: " + executeCommand + ", Failed, Status = " + status);
						/*
						 * Retrieve data from shadow file
						 */
						executeCommand = "cat /etc/shadow | awk -F ':' '{if($1 == \"" + nativeIdentifier + "\") print}'";
						retPrompt = sshCommandExecute(executeCommand);
						String[] shadowDBAcc = retPrompt.split(":", -1);
						for (String s : shadowDBAcc)
							System.out.println(s);
						for (int i = 0; i < shadowDB.size(); i++) {
							if (i != 1) {
								attribute = shadowDB.get(i);
								if (log.isDebugEnabled())
									log.debug("Current attribute=" + attribute);
								attrVal = shadowDBAcc[i];

								if (attrVal != null && log.isDebugEnabled())
									log.debug("Found in Shadow, value:" + attrVal);

								if (attrVal != null)
									updateObj.put(attribute, attrVal);
							}
						}
						status = 0;
						status = getShellExecutionStatus();
						if (status != 0)
							System.out.println("[ERROR] Shell Exeucte Command: " + executeCommand + ", Failed, Status = " + status);
					}else { // No Shadow file case
						/*
						 * Retrieve data from passwd file
						 */
						executeCommand = "cat /etc/passwd | awk -F ':' '{if($1 == \"" + nativeIdentifier + "\") print}'";
						retPrompt = sshCommandExecute(executeCommand);
						String[] passwdDBAcc = retPrompt.split(":", -1);
						String attribute;
						String attrVal;
						char pwdInfoDig;
						String pwdInfoDigDecoded;
						for (int i = 0; i < passwdDB.size(); i++) {
							if (i != 1) {
								attribute = passwdDB.get(i);
								if (log.isDebugEnabled())
									log.debug("Current attribute=" + attribute);
								attrVal = passwdDBAcc[i];

								if (attrVal != null && log.isDebugEnabled())
									log.debug("Found in Passwd, value:" + attrVal);

								if (attrVal != null)
									updateObj.put(attribute, attrVal);
							}else if(i ==1) { // Get the password field
								// Hard code to get the password age information
								attrVal = passwdDBAcc[i];
								if(attrVal.contains(",")) {
									int attrValLen = attrVal.length();
									int commaPos = attrVal.indexOf(",");
									if(commaPos < (attrValLen -1 )) {
										String pwdInfo = attrVal.substring(commaPos+1,attrValLen);
										int pwdInfoLen = pwdInfo.length();
										
										for(int j=0 ; j<pwdInfoLen ; j++) {
											if(j == 0) { // Contains Max
												pwdInfoDig = pwdInfo.charAt(j);
												pwdInfoDigDecoded = digitsMapping(pwdInfoDig);
												updateObj.put("pwdmax", pwdInfoDigDecoded);
											}else if(j == 1) { // Contains Min
												pwdInfoDig = pwdInfo.charAt(1);
												pwdInfoDigDecoded = digitsMapping(pwdInfoDig);
												updateObj.put("pwdmin", pwdInfoDigDecoded);
											}else {
												break;
											}
										}
										if(pwdInfoLen > 2) {
											if(pwdInfoLen == 3) {
												updateObj.put("pwdlastchg", pwdInfo.substring(2, 3));
											}else if(pwdInfoLen == 4) {
												updateObj.put("pwdlastchg", pwdInfo.substring(2, 4));
											}
										}
									}
								}else {
									if (log.isDebugEnabled())
										log.debug("No password aging information found...");
								}
							}
						}
						status = 0;
						status = getShellExecutionStatus();
						if (status != 0)
							System.out.println("[ERROR] Shell Exeucte Command: " + executeCommand + ", Failed, Status = " + status);
					}
					
					/*
					 * Get account status
					 */
					accStatus = getAccountActiveStatus(nativeIdentifier);
					if (log.isDebugEnabled())
						log.debug("Account " + nativeIdentifier + ",status:" + accStatus);
					if (accStatus.equals("Disabled"))
						updateObj.put("IIQDisabled", true);
					else if (accStatus.equals("Locked"))
						updateObj.put("IIQLocked", true);
					else {
						updateObj.put("IIQDisabled", false);
						updateObj.put("IIQLocked", false);
					}
					/*
					 * Get account lastLogin date
					 */
					String lastLogin = getLastLoginTimeInformation(nativeIdentifier);
					if (lastLogin != null) {
						updateObj.put("lastLogin", lastLogin);
					}
					if (log.isDebugEnabled())
						log.debug("Account " + nativeIdentifier + ",lastlogin:" + lastLogin);

				} else if (OBJECT_TYPE_GROUP.equals(this.objectType)) {
					if (log.isDebugEnabled())
						log.debug("Not Support Read Group Operation");
				}
			} else {

			}
			sshLogout();
		} catch (AccountNotFoundException anfe) {
			if (log.isDebugEnabled())
				System.out.println(nativeIdentifier + " not exists...");
			getObjectsMap().remove(nativeIdentifier);
			dump();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// If we're not updating, create a copy so the cache won't get
		// corrupted.
		exit(funcName);
		System.out.println("Read object:" + updateObj);
		return (forUpdate) ? updateObj : copy(obj);
	}

	/**
	 * Create a deep clone of the given map.
	 */
	private Map<String, Object> copy(Map<String, Object> obj) {
		// Should do a deeper clone here.
		return (null != obj) ? new HashMap<String, Object>(obj) : null;
	}

	/**
	 * Using for aggregate accounts Not yet configure for filter Not yet
	 * configure for group aggregate
	 * 
	 * @see openconnector.Connector#iterate(openconnector.Filter)
	 * @version - HPUXConnector 1.0.0
	 */
	@SuppressWarnings("unchecked")
	@Override
	public Iterator<Map<String, Object>> iterate(Filter filter) throws ConnectorException {
		String funcName = "Iterator()";
		enter(funcName);
		// Return the iterator on a copy of the list to avoid concurrent mod
		// exceptions if entries are added/removed while iterating.
		// Iterator<Map<String, Object>> it = new ArrayList<Map<String,
		// Object>>(getObjectsMap().values()).iterator();

		// Note: FilteredIterator should not be used for most connectors.
		// Instead, the filter should be converted to something that can be
		// used to filter results natively (eg - an LDAP search filter, etc...)
		// Wrap this in a CopyIterator so the cache won't get corrupted.
		// return new CopyIterator(new FilteredIterator(it, filter));
		getPasswdDBFormat();
		getShadowDBFormat();
		ArrayList<Map<String, Object>> data = new ArrayList<Map<String, Object>>();
		ArrayList<String> userList = new ArrayList<String>();
		Map<String, Map<String, Object>> eachAccounts = new HashMap<String, Map<String, Object>>();
		if (OBJECT_TYPE_ACCOUNT.equals(this.objectType)) {
			if (log.isDebugEnabled())
				log.debug("Aggregate Accounts Info...");
			try {
				String attribute, attrVal;
				Map<String, Object> eachAccount;
				sshLogin();
				//
				// Read data from passwd file
				//
				String executeCommand = "";
				executeCommand = "cat /etc/passwd | grep -v '^+' | grep -v '^-'";
				String retPrompt = sshCommandExecute(executeCommand);
				if (log.isDebugEnabled())
					log.debug(retPrompt);
				int status = getShellExecutionStatus();
				if (status != 0)
					System.out.println("[ERROR] Shell Exeucte Command: " + executeCommand + ", Failed, Status = " + status);
				String[] pAccs = retPrompt.split("\\r?\\n");
				for (String pAcc : pAccs) {
					eachAccount = new HashMap<String, Object>();
					String[] accAttrs = pAcc.split(":", -1);
					userList.add(accAttrs[0]);
					for (int i = 0; i < passwdDB.size(); i++) {
						if (i != 1) {
							attribute = passwdDB.get(i);
							if (log.isDebugEnabled())
								log.debug("Current attribute=" + attribute);
							attrVal = accAttrs[i];

							if (attrVal != null && log.isDebugEnabled())
								log.debug("Found in Passwd, value:" + attrVal);

							if (attrVal != null)
								eachAccount.put(attribute, attrVal);
						}
					}
					eachAccounts.put((String) eachAccount.get("username"), eachAccount);
				}

				//
				// Read data from shadow file
				//
				if (hasShadowFile) {
					executeCommand = "cat /etc/shadow | grep -v '^+' | grep -v '^-'";
					retPrompt = sshCommandExecute(executeCommand);
					if (log.isDebugEnabled())
						log.debug(retPrompt);
					status = getShellExecutionStatus();
					if (status != 0)
						System.out.println("[ERROR] Shell Exeucte Command: " + executeCommand + ", Failed, Status = " + status);
					String[] sAccs = retPrompt.split("\\r?\\n");
					for (String sAcc : sAccs) {
						String[] accAttrs = sAcc.split(":", -1);
						eachAccount = eachAccounts.get(accAttrs[0]);
						for (int i = 0; i < shadowDB.size(); i++) {
							if (i != 1) {
								attribute = shadowDB.get(i);
								if (log.isDebugEnabled())
									log.debug("Current attribute=" + attribute);
								attrVal = accAttrs[i];

								if (attrVal != null && log.isDebugEnabled())
									log.debug("Found in Shadow, value:" + attrVal);

								if (attrVal != null)
									eachAccount.put(attribute, attrVal);
							}
						}
						eachAccounts.put((String) eachAccount.get("username"), eachAccount);
					}
				}
				//
				// Get Account Status
				//
				for (String user : userList) {
					String accStatus = getAccountActiveStatus(user);
					if (log.isDebugEnabled())
						log.debug("Account " + user + ",status:" + accStatus);
					if (accStatus.equals("Disabled"))
						eachAccounts.get(user).put("IIQDisabled", true);
					else if (accStatus.equals("Locked"))
						eachAccounts.get(user).put("IIQLocked", true);
					else {
						eachAccounts.get(user).put("IIQDisabled", false);
						eachAccounts.get(user).put("IIQLocked", false);
					}
				}
				//
				// Generate Result
				//
				Iterator<?> eait = eachAccounts.entrySet().iterator();
				while (eait.hasNext()) {
					@SuppressWarnings("rawtypes")
					Map.Entry pair = (Map.Entry) eait.next();
					data.add((Map<String, Object>) pair.getValue());
				}
				sshLogout();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else if (OBJECT_TYPE_GROUP.equals(this.objectType)) {
			if (log.isDebugEnabled())
				log.debug("Not Support Aggregate Group Operation");
		}
		if (log.isDebugEnabled())
			System.out.println("Aggregate Return Data:" + data.toString());
		Iterator<Map<String, Object>> it = data.iterator();

		exit(funcName);
		return new CopyIterator(new FilteredIterator(it, filter));
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see openconnector.Connector#update
	 * @version - HPUXConnector 1.0.0
	 */
	@Override
	@SuppressWarnings("unchecked")
	public Result update(String nativeIdentifier, List<Item> items) throws ConnectorException, ObjectNotFoundException {

		Result result = new Result();

		Map<String, Object> existing = read(nativeIdentifier, true);
		if (null == existing) {
			throw new ObjectNotFoundException(nativeIdentifier);
		}
		try {
			sshLogin();
			if (session != null) {
				if (OBJECT_TYPE_ACCOUNT.equals(this.objectType)) {
					//
					// Update if Account Already Exists
					//
					if (!isAccountExists(nativeIdentifier)) {
						throw new Exception(nativeIdentifier + " not exists in the system");
					}
					if (log.isDebugEnabled())
						log.debug("Update Account NativeIdentitifer:" + nativeIdentifier);
					// setShellPrompt();
					//
					// Build Command
					//
					String updateCommand = "";
					if (config.getConfig().containsKey("modify.account")) {
						updateCommand = config.getString("modify.account");
					} else {
						if (log.isDebugEnabled())
							log.debug("Can't found update.account command, using default:usermod...");
						updateCommand = "usermod";
					}
					String executeCommand;
					//
					// Add command flags, incomplete
					//
					System.out.println("------------------ Update Account Options ----------------");
					if (items != null) {
						for (Item item : items) {
							String name = item.getName();
							Object value = item.getValue();
							Item.Operation op = item.getOperation();
							String flag = getAttributeMapValue(updateCommand, "flags", name);
							if (flag != null)
								executeCommand = updateCommand + " " + flag + " " + value + " " + nativeIdentifier;
							else
								continue;
							switch (op) {
							case Add: {
								List currentList = getAsList(existing.get(name));
								List values = getAsList(value);
								currentList.addAll(values);
								existing.put(name, currentList);
							}
								break;

							case Remove: {
								List currentList = getAsList(existing.get(name));
								List values = getAsList(value);
								currentList.removeAll(values);
								if (currentList.isEmpty())
									existing.remove(name);
								else
									existing.put(name, currentList);
							}
								break;

							case Set: {
								existing.put(name, value);
							}
								break;

							default:
								throw new IllegalArgumentException("Unknown operation: " + op);
							}
							sshCommandExecute(executeCommand);
							//
							// Get execution result status
							//
							int status = getShellExecutionStatus();
							if (status != 0) {
								String errorMsg = getAttributeMapValue(updateCommand, "exitsts", String.valueOf(status));
								if (errorMsg == null)
									errorMsg = "Update account encountered unexcepted error...";
								result.setStatus(Result.Status.Failed);
								result.add(errorMsg);
							} else {
								result.setStatus(Result.Status.Committed);
							}
						}
					}
					System.out.println("----------------------------------------------------------");
				} else if (OBJECT_TYPE_GROUP.equals(this.objectType)) {
					if (log.isDebugEnabled())
						log.debug("Not Support Create Group Operation");
					result = new Result(Result.Status.Committed);
				}
			} else {
				if (log.isDebugEnabled())
					log.debug("SSH session is LOST!!!");
				result = new Result(Result.Status.Failed);
				result.add("SSH session is LOST!!!");
			}
			sshLogout();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return result;
	}

	/**
	 * Delete Account userdel(1M) Delete options incomplete Reference:
	 * http://docstore.mik.ua/manuals/hp-ux/en/B2355-60130/userdel.1M.html
	 * 
	 * @see openconnector.Connector#delete(java.lang.String)
	 * @version - HPUXConnector 1.0.0
	 */
	@Override
	public Result delete(String nativeIdentifier, Map<String, Object> options) throws ConnectorException, ObjectNotFoundException {
		String funcName = "delete()";
		enter(funcName);
		Result result = new Result();
		try {
			sshLogin();
			if (session != null) {
				if (OBJECT_TYPE_ACCOUNT.equals(this.objectType)) {
					if (log.isDebugEnabled())
						log.debug("Delete Account NativeIdentitifer:" + nativeIdentifier);
					// setShellPrompt();
					// Build Command
					String deleteCommand = "";
					if (config.getConfig().containsKey("delete.account")) {
						deleteCommand = config.getString("delete.account");
					} else {
						if (log.isDebugEnabled())
							log.debug("Can't found delete.account command, using default:userdel...");
						deleteCommand = "userdel";
					}
					//
					// Add options incomplete...
					//
					// Add nativeIdentifier
					String executeCommand = deleteCommand + " " + nativeIdentifier;
					sshCommandExecute(executeCommand);

					// Get execution result status
					int status = getShellExecutionStatus();
					if (status != 0) {
						String errorMsg = getAttributeMapValue(deleteCommand, "exitsts", String.valueOf(status));
						if (errorMsg == null)
							errorMsg = "Delete account encountered unexcepted error...";
						result = new Result(Result.Status.Failed);
						result.add(errorMsg);
					} else {
						result.setStatus(Result.Status.Committed);
					}
				} else if (OBJECT_TYPE_GROUP.equals(this.objectType)) {
					if (log.isDebugEnabled())
						log.debug("Not Support Delete Group Operation");
					result.setStatus(Result.Status.Committed);
				}
			} else {
				if (log.isDebugEnabled())
					log.debug("SSH session is DONE!!!");
				result.setStatus(Result.Status.Failed);
				result.add("SSH session is DONE!!!");
			}
			sshLogout();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		Object removed = getObjectsMap().remove(nativeIdentifier);
		if (null == removed) {
			throw new ObjectNotFoundException(nativeIdentifier);
		}

		// djs: special code for unittesting Items get passed
		// correctly to this method via the options map.
		if (options != null) {
			Iterator<String> keys = options.keySet().iterator();
			if (keys != null) {
				while (keys.hasNext()) {
					String key = keys.next();
					// Add back any options so unittests can confirm
					// round trip
					result.add(key + ":" + options.get(key));
				}
			}
		}
		exit(funcName);
		return result;
	}

	// //////////////////////////////////////////////////////////////////////////
	//
	// EXTENDED OPERATIONS
	//
	// //////////////////////////////////////////////////////////////////////////

	/**
	 * Basic mode: passwd -f (Will make the account No Password ... security
	 * issue) Trusted mode: /usr/lbin/modprpw -k modprpw(1M) Reference:
	 * http://nixdoc.net/man-pages/HP-UX/modprpw.1m.html
	 * 
	 * @see openconnector.Connector#enable(java.lang.String)
	 * 
	 * @version - HPUXConnector 1.0.0
	 */
	@Override
	public Result enable(String nativeIdentifier, Map<String, Object> options) throws ConnectorException, ObjectNotFoundException {
		String funcName = "enable()";
		enter(funcName);
		Result result = new Result();
		try {
			sshLogin();
			if (session != null) {
				if (OBJECT_TYPE_ACCOUNT.equals(this.objectType)) {
					if (log.isDebugEnabled())
						log.debug("Enable Account NativeIdentitifer:" + nativeIdentifier);
					// setShellPrompt();
					// Build Command
					String enableCommand = "";
					if (isTrusted) {
						if (config.getConfig().containsKey("enable.account")) {
							enableCommand = config.getString("enable.account");
						} else {
							if (log.isDebugEnabled())
								log.debug("Can't found enable.account command, using default:passwd -d...");
							enableCommand = "passwd -d";
						}
					} else {
						if (config.getConfig().containsKey("enable.account.trusted")) {
							enableCommand = config.getString("enable.account.trusted");
						} else {
							if (log.isDebugEnabled())
								log.debug("Can't found enable.account.trusted command, using default:/usr/lbin/modprpw -k...");
							enableCommand = "/usr/lbin/modprpw -k";
						}
					}

					// Add nativeIdentifier
					String executeCommand = enableCommand + " " + nativeIdentifier;
					sshCommandExecute(executeCommand);

					// Get execution result status
					int status = getShellExecutionStatus();
					if (status != 0) {
						String errorMsg = getAttributeMapValue(enableCommand, "exitsts", String.valueOf(status));
						if (errorMsg == null)
							errorMsg = "Enable account encountered unexcepted error...";
						result = new Result(Result.Status.Failed);
						result.add(errorMsg);
					} else {
						result.setStatus(Result.Status.Committed);
					}
				} else if (OBJECT_TYPE_GROUP.equals(this.objectType)) {
					if (log.isDebugEnabled())
						log.debug("No Enable Group Operation");
					result.setStatus(Result.Status.Committed);
				}
			} else {
				if (log.isDebugEnabled())
					log.debug("SSH session is DONE!!!");
				result.setStatus(Result.Status.Failed);
				result.add("SSH session is DONE!!!");
			}
			sshLogout();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Check if account status is enabled
		Map<String, Object> obj = read(nativeIdentifier, true);
		if (null == obj) {
			throw new ObjectNotFoundException(nativeIdentifier);
		}

		obj.put(ATTR_DISABLED, false);
		exit(funcName);
		return result;
	}

	/**
	 * Basic mode: passwd -l issue) Trusted mode: /usr/lbin/modprpw -e
	 * modprpw(1M) Reference: http://nixdoc.net/man-pages/HP-UX/modprpw.1m.html
	 * 
	 * @see openconnector.Connector#enable(java.lang.String)
	 * 
	 * @version - HPUXConnector 1.0.0
	 */
	@Override
	public Result disable(String nativeIdentifier, Map<String, Object> options) throws ConnectorException, ObjectNotFoundException {
		String funcName = "disable()";
		enter(funcName);
		Result result = new Result();
		try {
			sshLogin();
			if (session != null) {
				if (OBJECT_TYPE_ACCOUNT.equals(this.objectType)) {
					if (log.isDebugEnabled())
						log.debug("Disable Account NativeIdentitifer:" + nativeIdentifier);
					// setShellPrompt();
					// Build Command
					String disableCommand = "";
					if (isTrusted) {
						if (config.getConfig().containsKey("disable.account")) {
							disableCommand = config.getString("disable.account");
						} else {
							if (log.isDebugEnabled())
								log.debug("Can't found disable.account command, using default:passwd -l...");
							disableCommand = "passwd -l";
						}
					} else {
						if (config.getConfig().containsKey("disable.account.trusted")) {
							disableCommand = config.getString("disable.account.trusted");
						} else {
							if (log.isDebugEnabled())
								log.debug("Can't found disable.account.trusted command, using default:/usr/lbin/modprpw -e...");
							disableCommand = "/usr/lbin/modprpw -e";
						}
					}

					// Add nativeIdentifier
					String executeCommand = disableCommand + " " + nativeIdentifier;
					sshCommandExecute(executeCommand);

					// Get execution result status
					int status = getShellExecutionStatus();
					if (status != 0) {
						String errorMsg = getAttributeMapValue(disableCommand, "exitsts", String.valueOf(status));
						if (errorMsg == null)
							errorMsg = "Disable account encountered unexcepted error...";
						result = new Result(Result.Status.Failed);
						result.add(errorMsg);
					} else {
						result.setStatus(Result.Status.Committed);
					}
				} else if (OBJECT_TYPE_GROUP.equals(this.objectType)) {
					if (log.isDebugEnabled())
						log.debug("No Enable Group Operation");
					result.setStatus(Result.Status.Committed);
				}
			} else {
				if (log.isDebugEnabled())
					log.debug("SSH session is DONE!!!");
				result.setStatus(Result.Status.Failed);
				result.add("SSH session is DONE!!!");
			}
			sshLogout();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		Map<String, Object> obj = read(nativeIdentifier, true);
		if (null == obj) {
			throw new ObjectNotFoundException(nativeIdentifier);
		}

		obj.put(ATTR_DISABLED, true);
		exit(funcName);
		return result;
	}

	/**
	 * Unlock account: userdbset -d -u userdbset(1M)
	 * http://docstore.mik.ua/manuals/hp-ux/en/B2355-60130/userdbset.1M.html
	 * security(4)
	 * http://docstore.mik.ua/manuals/hp-ux/en/B2355-60130/security.4.html *
	 * 
	 * @see openconnector.Connector#unlock(java.lang.String)
	 * @version - HPUXConnector 1.0.0
	 */
	@Override
	public Result unlock(String nativeIdentifier, Map<String, Object> options) throws ConnectorException, ObjectNotFoundException {

		String funcName = "unlock()";
		enter(funcName);
		Result result = new Result();
		try {
			sshLogin();
			if (session != null) {
				if (OBJECT_TYPE_ACCOUNT.equals(this.objectType)) {
					if (log.isDebugEnabled())
						log.debug("Disable Account NativeIdentitifer:" + nativeIdentifier);
					// setShellPrompt();
					// Build Command
					String unlockCommand = "";
					if (config.getConfig().containsKey("unlock.account")) {
						unlockCommand = config.getString("unlock.account");
					} else {
						if (log.isDebugEnabled())
							log.debug("Can't found disable.account.trusted command, using default:userdbset -d -u <username> auth_failures...");
						unlockCommand = "userdbset -d -u";
					}

					// Add nativeIdentifier
					String executeCommand = unlockCommand + " " + nativeIdentifier + " auth_failures";
					sshCommandExecute(executeCommand);

					// Get execution result status
					int status = getShellExecutionStatus();
					if (status != 0) {
						String errorMsg = getAttributeMapValue(unlockCommand, "exitsts", String.valueOf(status));
						if (errorMsg == null)
							errorMsg = "Unlock account encountered unexcepted error...";
						result = new Result(Result.Status.Failed);
						result.add(errorMsg);
					} else {
						result.setStatus(Result.Status.Committed);
					}
				} else if (OBJECT_TYPE_GROUP.equals(this.objectType)) {
					if (log.isDebugEnabled())
						log.debug("No Unlock Group Operation");
					result.setStatus(Result.Status.Committed);
				}
			} else {
				if (log.isDebugEnabled())
					log.debug("SSH session is DONE!!!");
				result.setStatus(Result.Status.Failed);
				result.add("SSH session is DONE!!!");
			}
			sshLogout();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		Map<String, Object> obj = read(nativeIdentifier, true);
		if (null == obj) {
			throw new ObjectNotFoundException(nativeIdentifier);
		}

		obj.put(ATTR_LOCKED, false);

		return result;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see openconnector.Connector#setPassword(java.lang.String,
	 * java.lang.String, java.lang.String, java.util.Map)
	 */
	@Override
	public Result setPassword(String nativeIdentifier, String newPassword, String currentPassword, Date expiration, Map<String, Object> options) throws ConnectorException, ObjectNotFoundException {

		Result result = new Result();

		Map<String, Object> obj = read(nativeIdentifier, true);
		if (null == obj) {
			throw new ObjectNotFoundException(nativeIdentifier);
		}
		try {
			sshLogin();
			if (session != null) {
				if (OBJECT_TYPE_ACCOUNT.equals(this.objectType)) {

					if (log.isDebugEnabled())
						log.debug("Set Password NativeIdentitifer:" + nativeIdentifier);
					// setShellPrompt();
					//
					// Build Command
					//
					String passwdCommand = "";
					if (config.getConfig().containsKey("change.password")) {
						passwdCommand = config.getString("change.password");
					} else {
						if (log.isDebugEnabled())
							log.debug("Can't found change.password command, using default:passwd...");
						passwdCommand = "passwd";
					}

					// Add nativeIdentifier
					String executeCommand = passwdCommand + " " + nativeIdentifier;
					// need to send password to sshCommandExecute
					// -------------------!!!!
					sshInteractiveSetPassword(executeCommand, newPassword, currentPassword);

					// Get execution result status
					int status = getShellExecutionStatus();
					if (status != 0) {
						String errorMsg = getAttributeMapValue(passwdCommand, "exitsts", String.valueOf(status));
						if (errorMsg == null)
							errorMsg = "SetPassword account encountered unexcepted error...";
						result.setStatus(Result.Status.Failed);
						result.add(errorMsg);
					} else {
						result.setStatus(Result.Status.Committed);
					}
					//
					// Exeucte each option separately
					//
					System.out.println("------------------ Set Password Options ----------------");
					if (options != null) {
						for (Map.Entry<String, Object> option : options.entrySet()) {
							String key = option.getKey();
							String value = (String) option.getValue();
							System.out.println("Key : " + key + " Value : " + value);
							String flag = getAttributeMapValue(passwdCommand, "flags", key);
							if (flag != null) {
								executeCommand = passwdCommand + " " + flag + " " + value;
								sshCommandExecute(executeCommand);
								status = getShellExecutionStatus();
								if (status != 0) {
									String errorMsg = getAttributeMapValue(passwdCommand, "exitsts", String.valueOf(status));
									if (errorMsg == null)
										errorMsg = "SetPassword account encountered unexcepted error...";
									result.add(errorMsg);
								}
							}
						}
					}
					System.out.println("----------------------------------------------------------");
				} else if (OBJECT_TYPE_GROUP.equals(this.objectType)) {
					if (log.isDebugEnabled())
						log.debug("No SetPassword Group Operation");
					result.setStatus(Result.Status.Failed);
				}
			} else {
				if (log.isDebugEnabled())
					log.debug("SSH session is DONE!!!");
				result.setStatus(Result.Status.Failed);
				result.add("SSH session is DONE!!!");
			}
			sshLogout();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		obj.put(ATTR_PASSWORD, newPassword);

		// expiration is stored in the options map in here
		if (expiration != null) {
			if (options == null)
				options = new HashMap<String, Object>();
			options.put(ARG_EXPIRATION, expiration);
		}
		obj.put(ATTR_PASSWORD_OPTIONS, options);

		if (null != currentPassword) {
			@SuppressWarnings("unchecked")
			List<String> history = (List<String>) obj.get(ATTR_PASSWORD_HISTORY);
			if (null == history) {
				history = new ArrayList<String>();
				obj.put(ATTR_PASSWORD_HISTORY, history);
			}
			history.add(currentPassword);
		}

		return result;
	}

	// //////////////////////////////////////////////////////////////////////////
	//
	// ADDITIONAL FEATURES
	//
	// //////////////////////////////////////////////////////////////////////////

	/*
	 * (non-Javadoc)
	 * 
	 * @see openconnector.Connector#authenticate(java.lang.String,
	 * java.lang.String)
	 */
	@Override
	public Map<String, Object> authenticate(String identity, String password) throws ConnectorException, ObjectNotFoundException, AuthenticationFailedException, ExpiredPasswordException {

		Map<String, Object> obj = read(identity);
		if (null == obj) {
			throw new ObjectNotFoundException(identity);
		}

		String actualPassword = (String) obj.get(ATTR_PASSWORD);

		// If the password matches, check the expiration if there is one.
		if ((null != actualPassword) && actualPassword.equals(password)) {
			@SuppressWarnings("unchecked")
			Map<String, Object> passwordsOptions = (Map<String, Object>) obj.get(ATTR_PASSWORD_OPTIONS);
			if (null != passwordsOptions) {
				Date expiration = (Date) passwordsOptions.get(ARG_EXPIRATION);
				if ((null != expiration) && expiration.before(new Date())) {
					throw new ExpiredPasswordException(identity);
				}
			}
		} else {
			// Passwords don't match.
			throw new AuthenticationFailedException();
		}

		// If there was a problem we would have thrown already. Return the
		// matched object.
		return obj;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see openconnector.Connector#discoverSchema()
	 */
	@Override
	public Schema discoverSchema() {
		Schema schema = new Schema();

		if (OBJECT_TYPE_ACCOUNT.equals(this.objectType)) {
			schema.addAttribute(ATTR_USERNAME);
			schema.addAttribute(ATTR_UID, Schema.Type.STRING);
			schema.addAttribute(ATTR_GID, Schema.Type.STRING);
			schema.addAttribute(ATTR_COMMENT, Schema.Type.STRING);
			schema.addAttribute(ATTR_GROUPS, Schema.Type.STRING);
			schema.addAttribute(ATTR_PWDLASTCHG, Schema.Type.INT);
			schema.addAttribute(ATTR_PWDMIN, Schema.Type.INT);
			schema.addAttribute(ATTR_PWDMAX, Schema.Type.INT);
			schema.addAttribute(ATTR_PWDWARN, Schema.Type.INT);
			schema.addAttribute(ATTR_INACTIVE, Schema.Type.INT);
		} else {
			schema.addAttribute(GROUP_ATTR_NAME);
			schema.addAttribute(GROUP_ATTR_DESCRIPTION);
		}

		return schema;
	}

	// //////////////////////////////////////////////////////////////////////////
	//
	// SIMPLE TEST - TODO: Pull this out into an actual unit test...
	//
	// //////////////////////////////////////////////////////////////////////////

	public static void main(String[] args) throws Exception {

		// ConnectorConfig config = new ConnectorConfig();
		// config.setConfig(new HashMap<String, Object>());
		// HPUXConnector HPUXConn = new HPUXConnector(config, new
		// SystemOutLog());

		// Schema schema = new Schema();
		// schema.setObjectType(OBJECT_TYPE_ACCOUNT);
		// schema.setIdentityAttribute(ATTR_USERNAME);
		// config.addSchema(schema);

		// TODO: example of a few config parameters ... a transformer of some
		// flavor (ie - java interface) to show how to implement hooks, a
		// boolean, an int, and a string?

		// HPUXConnector conn = new HPUXConnector(config, new SystemOutLog());
		// startTest("Initial state");
		// startTest("TestConnection");
		// HPUXConn.testConnection();
		// dump();

		// startTest("isAccountExists");
		// boolean res = HPUXConn.isAccountExists("testing223");
		// System.out.println(res);

		// startTest("Read()");
		// Map<String, Object> testing = HPUXConn.read("testing");

		// startTest("Iterate()");
		// HPUXConn.iterate(new Filter());
		// startTest("Set Password");
		// HPUXConn.setPassword("uattest02", "newpassword123", "newpassword",
		// null, null);
		// dump();
		// System.out.println("Read jdoe: " + testing);
		// startTest("Create"); List<Item> items = new ArrayList<Item>();
		// items.add(new Item(ATTR_FIRSTNAME, "new")); items.add(new
		/*
		 * Item(ATTR_LASTNAME, "USER")); items.add(new Item(ATTR_EMAIL,
		 * "new.user@example.com")); items.add(new Item(ATTR_PASSWORD,
		 * "secret2")); List<String> groups = new ArrayList<String>();
		 * groups.add("group2"); items.add(new Item(ATTR_GROUPS, groups));
		 * 
		 * conn.create("newuser", items); dump();
		 * 
		 * startTest("Read"); Map<String, Object> jdoe = conn.read("jdoe");
		 * System.out.println("Read jdoe: " + jdoe);
		 * 
		 * startTest("Iterate"); Iterator<Map<String, Object>> it =
		 * conn.iterate((Filter) null); while (it.hasNext()) {
		 * System.out.println(it.next()); }
		 * 
		 * startTest("Iterate with filter"); Filter f = new Filter();
		 * f.add(ATTR_USERNAME, Filter.Operator.STARTS_WITH, "j"); it =
		 * conn.iterate(f); while (it.hasNext()) {
		 * System.out.println(it.next()); }
		 * 
		 * startTest("Update"); items = new ArrayList<Item>(); items.add(new
		 * Item(ATTR_LASTNAME, "Reilly")); conn.update("jdoe", items); dump();
		 * 
		 * startTest("Update with UpdateOptions"); items = new
		 * ArrayList<Item>(); items.add(new Item(ATTR_FIRSTNAME, "Bruce"));
		 * items.add(new Item(ATTR_LASTNAME, "Lee")); List<String> toAdd = new
		 * ArrayList<String>(); toAdd.add("foo"); toAdd.add("bar");
		 * items.add(new Item(ATTR_GROUPS, Item.Operation.Add, toAdd));
		 * List<String> toRemove = new ArrayList<String>();
		 * toRemove.add("group2"); items.add(new Item(ATTR_GROUPS,
		 * Item.Operation.Remove, toRemove)); conn.update("jdoe", items);
		 * dump();
		 * 
		 * startTest("Delete"); conn.delete("jdoe", null); dump();
		 * 
		 * startTest("Disable"); conn.disable("jsmith", null); dump();
		 * 
		 * startTest("Enable"); conn.enable("jsmith", null); dump();
		 * 
		 * startTest("Unlock"); conn.unlock("jsmith", null); dump();
		 * 
		 * startTest("Set Password"); conn.setPassword("jsmith", "newpassword",
		 * "secret", null, null); dump();
		 * 
		 * startTest("Authenticate"); Map<String, Object> authenticated =
		 * conn.authenticate("jsmith", "newpassword");
		 * System.out.println(authenticated);
		 * 
		 * startTest("Authenticate with expiration"); Date expiration = new
		 * Date(System.currentTimeMillis() + 50); conn.setPassword("jsmith",
		 * "secret", "newpassword", expiration, null); Thread.sleep(100); try {
		 * authenticated = conn.authenticate("jsmith", "newpassword");
		 * System.out .println(
		 * "PROBLEM!!  Authenticating with expired password should have failed."
		 * ); } catch (ExpiredPasswordException e) { System.out
		 * .println("Authenticating with expired password did not allow access: "
		 * + e.getMessage()); }
		 */
	}

	private static boolean firstTest = true;

	private static void startTest(String name) {
		if (!firstTest) {
			System.out.println("\n");
		}
		System.out.println("--- " + name.toUpperCase() + " ---");
		firstTest = false;
	}

}
