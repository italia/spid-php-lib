<?php

use Italia\Spid\Spid\Saml\Idp;
use Italia\Spid\Spid\Saml\Out\AuthnRequest;
use Italia\Spid\Spid\Saml\In\BaseResponse;
use \PDO;
use \PDOException;

class Db {
	
	public $idp;
	private $dbType;
	private $dbHost;
	private $dbInstance;
	private $dbName;
	private $tableName;
	private $dbUser;
	private $dbPassword;
	private $conn;
	
	public function __construct(Idp $idp)
    {
		$this->idp = $idp;
		$this->dbType = $this->idp->sp->settings['database']['type'];
		$this->dbHost = $this->idp->sp->settings['database']['host'];
		$this->dbInstance = $this->idp->sp->settings['database']['instance'];
		$this->dbName = $this->idp->sp->settings['database']['name'];
        $this->tableName = $this->idp->sp->settings['database']['table_name'];
		$this->dbUser = $this->idp->sp->settings['database']['user'];
		$this->dbPassword = $this->idp->sp->settings['database']['password'];
		$this->createTableIfNotExist();
    }
	
	private function createConn() {
		if($this->dbType == 'mysql') {
			try {
				$conn = new PDO("mysql:host=".$this->dbHost.";dbname=".$this->dbName, $this->dbUser, $this->dbPassword);
				$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
			} catch(PDOException $e) {
				$conn = null;
                throw new \Exception($e->getMessage());
			}
		}
		if($this->dbType == 'sqlserver') {
			$serverName = $this->dbHost;
			if($this->dbInstance) {
				$serverName = $serverName."\\".$this->dbInstance;
			}
			$connectionInfo = array("Database"=>$this->dbName, "UID"=>$this->dbUser, "PWD"=>$this->dbPassword);
			$conn = sqlsrv_connect($serverName, $connectionInfo);
		}
		return $conn;
	}
	
	private function createTableIfNotExist() {
		$conn = $this->createConn();
		
		if($this->dbType == 'mysql') {
			$sql = 'CREATE TABLE IF NOT EXISTS `' . $this->tableName . '` ( `ID` int NOT NULL AUTO_INCREMENT, `AUTHNREQUEST` mediumtext COLLATE utf8mb4_unicode_ci NOT NULL, `RESPONSE` mediumtext CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci, `AUTHNREQ_ID` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL, `AUTHNREQ_ISSUEINSTANT` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL, `RESP_ID` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL, `RESP_ISSUEINSTANT` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL, `RESP_ISSUER` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL, `ASSERTION_ID` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL, `ASSERTION_SUBJECT` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL, `ASSERTION_SUBJECT_NAMEQUALIFIER` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL, PRIMARY KEY (`ID`)) ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;';
			$conn->exec($sql);
		}
		
		if($this->dbType == 'sqlserver') {
			$sql = 'IF NOT EXISTS (SELECT [name] FROM sys.tables where [name] = \'' . $this->tableName . '\') CREATE TABLE ' . $this->tableName . ' (	[ID] [bigint] IDENTITY(1,1) NOT NULL, [AUTHNREQUEST] [nvarchar](max) NOT NULL, [RESPONSE] [nvarchar](max) NULL, [AUTHNREQ_ID] [nvarchar](max) NULL,	[AUTHNREQ_ISSUEINSTANT] [nvarchar](max) NULL, [RESP_ID] [nvarchar](max) NULL,	[RESP_ISSUEINSTANT] [nvarchar](max) NULL, [RESP_ISSUER] [nvarchar](max) NULL, [ASSERTION_ID] [nvarchar](max) NULL, [ASSERTION_SUBJECT] [nvarchar](max) NULL, [ASSERTION_SUBJECT_NAMEQUALIFIER] [nvarchar](max) NULL) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]';
			$result = sqlsrv_query($conn, $sql);
		}
		$this->closeConn($conn);
	}
	
	public function insertAuthnDataIntoLog() {
		$conn = $this->createConn();
		$authnReq = $this->idp->getAuthn();
		$authnReqXML = $authnReq->xml;
		$authnReqID = $authnReq->id;
		$authnReqIssueIstant = $authnReq->issueInstant;
		$assertionID = $this->idp->assertID;
		if($this->dbType == 'mysql') {
			$sql = "INSERT INTO " . $this->tableName . " (AUTHNREQUEST, AUTHNREQ_ID, AUTHNREQ_ISSUEINSTANT, ASSERTION_ID) VALUES ('".$authnReqXML."', '".$authnReqID."', '".$authnReqIssueIstant."', ".$assertionID.")";
			$conn->exec($sql);
			$_SESSION['LogID'] = $conn->lastInsertId();
		}
		if($this->dbType == 'sqlserver') {
			$query = "INSERT INTO " . $this->tableName . " (AUTHNREQUEST, AUTHNREQ_ID, AUTHNREQ_ISSUEINSTANT, ASSERTION_ID) VALUES (?, ?, ?, ?); SELECT SCOPE_IDENTITY()";
			$params = array($authnReqXML, $authnReqID, $authnReqIssueIstant, $assertionID);
			$result = sqlsrv_query($conn, $query, $params);
			sqlsrv_next_result($result); 
			sqlsrv_fetch($result); 
			$_SESSION['LogID'] = sqlsrv_get_field($result, 0);
		}
		$this->closeConn($conn);
	}
	
	public function updateLogWithResponseData(BaseResponse $response) {
		if(isset($_SESSION['LogID'])) {
			$conn = $this->createConn();
			$logID = $_SESSION['LogID'];
			$responseXML = $response->getXml();
			if($responseXML) {
				$responseXMLString = simplexml_import_dom($responseXML)->asXML();
				$responseID = $responseXML->getAttribute('ID');
				$responseIssueInstant = $responseXML->getAttribute('IssueInstant');
				$responseIssuer = $responseXML->getElementsByTagName('Issuer')->item(0)->nodeValue;
				$assertionSubject = simplexml_import_dom($responseXML->getElementsByTagName('Assertion')->item(0)->getElementsByTagName('Subject')->item(0))->asXML();
				$assertionSubjectNameQualifier = $responseXML->getElementsByTagName('Assertion')->item(0)->getElementsByTagName('Subject')->item(0)->getElementsByTagName('NameID')->item(0)->getAttribute('NameQualifier');
				if($this->dbType == 'mysql') {
					$sql = "UPDATE " . $this->tableName . " SET RESPONSE = '".$responseXMLString."', RESP_ID = '".$responseID."', RESP_ISSUEINSTANT = '".$responseIssueInstant."', RESP_ISSUER = '".$responseIssuer."', ASSERTION_SUBJECT = '".$assertionSubject."', ASSERTION_SUBJECT_NAMEQUALIFIER = '".$assertionSubjectNameQualifier."' WHERE ID = ".$logID."";
					$conn->exec($sql);
				}
				if($this->dbType == 'sqlserver') {
					$query = "UPDATE " . $this->tableName . " SET RESPONSE = ?, RESP_ID = ?, RESP_ISSUEINSTANT = ?, RESP_ISSUER = ?, ASSERTION_SUBJECT = ?, ASSERTION_SUBJECT_NAMEQUALIFIER = ? WHERE ID = ?";
					$params = array($responseXMLString, $responseID, $responseIssueInstant, $responseIssuer, $assertionSubject, $assertionSubjectNameQualifier, $logID);
					$result = sqlsrv_query($conn, $query, $params);
				}
			}
			unset($_SESSION['LogID']);
			$this->closeConn($conn);
		}
	}
	
	private function closeConn(&$conn) {
		if($this->dbType == 'mysql') {
			if($conn) {
				$conn = null;
			}
		}
		if($this->dbType == 'sqlserver') {
			if($conn) {
				sqlsrv_close($conn);
			}
		}
	}

}

?>