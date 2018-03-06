package org.cisecurity.ietf.sacm.tst

import com.xebialabs.overthere.CmdLine
import groovy.xml.XmlUtil
import groovyx.net.http.ContentType
import groovyx.net.http.RESTClient
import org.cisecurity.assessor.impl.DatastreamCollectionEngine
import org.cisecurity.assessor.impl.OvalDefinitionsEngine
import org.cisecurity.assessor.impl.XccdfCollectionEngine
import org.cisecurity.assessor.impl.status.ConsoleStatusWriter
import org.cisecurity.assessor.intf.IChecklistEngine
import org.cisecurity.assessor.intf.IDatastreamEngine
import org.cisecurity.assessor.parser.file.DatastreamCollectionParser
import org.cisecurity.assessor.parser.file.OvalDefinitionsCollectionParser
import org.cisecurity.assessor.parser.file.XccdfCollectionParser
import org.cisecurity.assessor.util.AssessorUtilities
import org.cisecurity.session.fact.ISessionFactory
import org.cisecurity.session.fact.SessionConfig
import org.cisecurity.session.fact.SessionFactoryFactory
import org.cisecurity.session.intf.ISession
import org.cisecurity.util.ExitValues
import org.jivesoftware.smack.AbstractXMPPConnection
import org.jivesoftware.smack.ConnectionConfiguration
import org.jivesoftware.smack.SmackException
import org.jivesoftware.smack.XMPPException
import org.jivesoftware.smack.tcp.XMPPTCPConnection
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration
import org.jivesoftware.smackx.httpfileupload.HttpFileUploadManager
import org.jivesoftware.smackx.httpfileupload.element.Slot
import org.jivesoftware.smackx.pubsub.AccessModel
import org.jivesoftware.smackx.pubsub.ConfigureForm
import org.jivesoftware.smackx.pubsub.ItemPublishEvent
import org.jivesoftware.smackx.pubsub.LeafNode
import org.jivesoftware.smackx.pubsub.PayloadItem
import org.jivesoftware.smackx.pubsub.PubSubManager
import org.jivesoftware.smackx.pubsub.PublishModel
import org.jivesoftware.smackx.pubsub.SimplePayload
import org.jivesoftware.smackx.pubsub.listener.ItemEventListener
import org.jivesoftware.smackx.xdata.packet.DataForm
import org.slf4j.LoggerFactory

/**
 * Created by wmunyan on 2/23/2018.
 */
class TopicWrapper {
	def log = LoggerFactory.getLogger(TopicWrapper.class)

	XMPPTCPConnectionConfiguration config
	AbstractXMPPConnection         connection
	PubSubManager                  pubsubManager
	HttpFileUploadManager          fileUploadManager
	LeafNode                       topicNode

	def topicName

	def initialized = false

	def initialize() {
		log.info "Loading Assessor properties..."
		AssessorUtilities.instance.userProperties = new Properties()
		AssessorUtilities.instance.userProperties.load(getClass().getResourceAsStream("/assessor.properties"))

		log.info "Loading XMPP connection properties..."
		Properties properties = new Properties()
		properties.load(getClass().getResourceAsStream("/conn.properties"))

		log.info "Configuring XMPP connection..."
		config = XMPPTCPConnectionConfiguration.builder()
			.setUsernameAndPassword(properties.contentpublisheruser, properties.contentpublisherpwd)
			.setXmppDomain(properties.xmppdomain)
			.setHost(properties.host)
			.setPort(Integer.parseInt(properties.port))
			.setSecurityMode(ConnectionConfiguration.SecurityMode.disabled)
			.build()

		log.info "Connecting to XMPP server as user ${properties.contentpublisheruser}..."
		connection = new XMPPTCPConnection(config)
		connection.setReplyTimeout(45000) // Reply timeout == 45 sec.
		connection.connect().login()

		log.info "Getting the PubSubManager..."

		// Create a pubsub manager using an existing XMPPConnection
		pubsubManager = PubSubManager.getInstance(connection)
		fileUploadManager = HttpFileUploadManager.getInstanceFor(connection)

		initialized = true
	}

	/**
	 * Disconnect from the XMPP server
	 * @return
	 */
	def disconnect() {
		if (initialized) {
			connection.disconnect()
		}
	}

	def retrieveOrCreateTopic() {
		if (!initialized) { initialize() }

		log.info "Attempting to retrieve topic --> ${topicName}"

		retrieveTopic()
		if (!topicNode) {
			log.info "Unable to retrieve topic '${topicName}'.  Attempting to create it..."
			createTopic()

			if (topicNode) {
				log.info "Successfully created topic '${topicName}'."
			} else {
				log.info "Unable to create topic '${topicName}'"
			}
		}
	}
	/**
	 * Retrieve an existing topic
	 * @return
	 */
	def retrieveTopic() {
		if (!initialized) { initialize() }

		log.info "Attempting to retrieve topic --> ${topicName}"

		try {
			topicNode = pubsubManager.getLeafNode(topicName)

			log.info "Found topic --> ${topicName}"
		} catch (XMPPException.XMPPErrorException e) {
			log.error "Exception when retrieving topic --> ${topicName}", e
		}
	}

	/**
	 * Create a topic
	 */
	def createTopic() {
		ConfigureForm form = new ConfigureForm(DataForm.Type.submit)
		form.setAccessModel(AccessModel.open)
		form.setDeliverPayloads(true)
		form.setMaxPayloadSize(78643200) // 75MB
		form.setNotifyRetract(true)
		form.setPersistentItems(true)
		form.setPublishModel(PublishModel.open)

		try {
			topicNode = pubsubManager.createNode(topicName, form)
		} catch (XMPPException.XMPPErrorException e) {
			log.error "Exception when creating topic --> ${topicName}", e
		}
	}

	/**
	 * Publish a collection to the topic
	 * @param filepath
	 * @return
	 */
	def publishCollection(def filepath) {
		// Open the file...
		def f = new File(filepath)
		if (f.exists()) {
			def collectionNode = AssessorUtilities.instance.getParser().parse(f)
			def rootBasename = getElementBasename(collectionNode.name())

			if (rootBasename == "data-stream-collection") {
				def collectionId = collectionNode.@id.toString()

				log.info "Constructing payload for collection id --> ${collectionId}..."
				log.info "Getting Slot..."
				Slot slot = fileUploadManager.requestSlot(f.name, f.length())

				log.info "GET URL --> ${slot.getUrl}"
				log.info "PUT URL --> ${slot.putUrl}"

				def rest = new RESTClient(slot.putUrl)
				rest.ignoreSSLIssues()
				def restresponse = rest.put(
					contentType: ContentType.XML,
					body: f.text,
					headers: [Accept: "application/xml"]
				)

				if (restresponse.status == 201) {
					def payloadContent =
						"<dsc_get_url xmlns=\"pubsub:dsc:url\">${slot.getUrl.toString()}</dsc_get_url>"
					def sp = new SimplePayload(
						"dsc_get_url",
						"pubsub:dsc:url",
						payloadContent
					)
					def pi = new PayloadItem(collectionId, sp)

					// Publish an Item with payload
					try {
						topicNode.publish(pi)

						log.info "Published"
					} catch (SmackException.NoResponseException nre) {
						log.error "No Response Exception: Probably a timeout", nre
					}
				} else {
					log.info "File upload response status == ${restresponse.status}"
				}


//				def sp = new SimplePayload(
//					"data-stream-collection",
//					"http://scap.nist.gov/schema/scap/source/1.2",
//					f.text)
//
//				log.info "Payload size is ${f.length()}..."
//
//				def pi = new PayloadItem(collectionId, sp)
//
//				log.info "Publishing payload to topic..."
//
//				// Publish an Item with payload
//				topicNode.publish(pi)
			} else {
				log.error "Invalid payload (${rootBasename}) for topic."
			}
		} else {
			log.error "Payload file at ${filepath} does not exist."
		}
	}

	def retrieveCollection() {
		log.info "Retrieving persisted items"

		def persistedItems = topicNode.items

		def assessorQueue = []

		log.info "Retrieved ${persistedItems.size()} items"
		persistedItems.eachWithIndex { item, i ->
			def ifp = "C:\\Temp\\XMPP-Item-${i+1}.xml"
			log.info "Writing File --> ${ifp}"

			def itemNode = AssessorUtilities.instance.getParser().parseText(item.toXML())
			def payloadNode = itemNode.children()[0]

			def payloadBasename = getElementBasename(payloadNode.name())
			if (payloadBasename == "data-stream-collection") {
				new File(ifp).withWriter { w ->
					w.write XmlUtil.serialize(payloadNode)
				}
				assessorQueue << ifp
			} else {
				log.error "Invalid payload on topic -- ${payloadBasename}"
			}
			log.info "Deleting item from topic --> ${item.getId()}"
			topicNode.deleteItem(item.getId())
		}

		if (assessorQueue.size() > 0) {
			assessorQueue.each { fp ->
				def (title, engine, parser) = collectAssessmentEngineParser(new File(fp))

				if (engine && parser) {
					log.info "Assessing ------> ${title}"

					// Parse for engine parameters...
					engine.parameters = parser.parseForParameters()
					engine.initializeCollection()

					// Schema Validations...
					def pe = engine.validate()
					if (pe.size() > 0) {
						log.error "------------------------ Schema Validation Errors ---------------------------"
						pe.each { log.error it }
						log.error "-----------------------------------------------------------------------------"
						System.exit(ExitValues.EV_SCHEMA_VALIDATION_ERRORS)
					}

					IDatastreamEngine datastreamEngine = engine.selectDatastream(0)
					IChecklistEngine checklistEngine = datastreamEngine.selectChecklist(0)
					checklistEngine.selectProfile(0)

					// Configure status writer (Console for now)
					def statusWriter = new ConsoleStatusWriter()
					statusWriter.initialize()
					checklistEngine.statusWriter = statusWriter
					checklistEngine.checklistProperties = AssessorUtilities.instance.userProperties

					//collectInteractiveValues(checklistEngine)

					def session = initializeDefaultSession()

					engine.session = checklistEngine.session = session
					checklistEngine.transform()
					checklistEngine.evaluate()

					generateResults(engine)

					session.disconnect()
				}
			}
		} else {
			log.info "No valid payloads were retrieved from the node."
		}
	}

	/**
	 * Create the IDatastreamCollectionEngine/Parser
	 * @param file
	 * @return
	 */
	def collectAssessmentEngineParser(File file) {
		def root = AssessorUtilities.instance.getParser().parse(file) // NOTE: This exits CIS-CAT if the file does not exist.
		def rootBasename = AssessorUtilities.instance.getElementBasename(root.name())

		log.info "Assessment File --> ${file.canonicalPath}"

		def title
		def engine
		def parser

		switch (rootBasename) {
			case "Benchmark":
				def t = root.children().find { n ->
					AssessorUtilities.instance.getElementBasename(n.name()) == "title"
				}
				title  = t.text()
				engine = new XccdfCollectionEngine(engineIdentifier: t.text())
				parser = new XccdfCollectionParser(
					basePath: System.getProperty("user.dir"),
					collectionFilepath: file.canonicalPath)
				break
			case "data-stream-collection":
				title  = root.@id.toString()
				engine = new DatastreamCollectionEngine(engineIdentifier: root.@id)
				parser = new DatastreamCollectionParser(collectionFilepath: file.canonicalPath)
				break
			case "oval_definitions":
				title = "OVAL Definitions - ${file.name}"
				engine = new OvalDefinitionsEngine(engineIdentifier: "OVAL Definitions - ${file.name}")
				parser = new OvalDefinitionsCollectionParser(collectionFilepath: file.canonicalPath)
			default:
				break // Skip
		}
		return [title, engine, parser]
	}

	/**
	 * Initialize a local session
	 * @return
	 */
	def initializeDefaultSession() {
		// Account for running in IDE...
		def localScriptsPath = "C:\\_Development\\Projects\\Shared\\scripts"

		SessionConfig cfg =
			new SessionConfig(
				type: SessionConfig.Type.LOCAL,
				localScriptsDirPathname: localScriptsPath
			)

		// Obtain the session...
		ISessionFactory factory = new SessionFactoryFactory().getSessionFactory()
		ISession defaultSession = factory.getSession(cfg)

		// Once the session is connected, we may have to unzip the "scripts" folder to
		// be able to access all the compile python functions...
		if (defaultSession.isWindows()) {
			log.info "Connection type is Windows:"
			log.info "--> Unzipping [START]"
			def unzipCmd = "${defaultSession.connectionTmpPathname}unzip.exe"
			def zipfile  = "${defaultSession.connectionTmpPathname}scripts.zip"
			CmdLine cl = CmdLine.build(unzipCmd, "-o", "-qq", zipfile, "-d", defaultSession.connectionTmpPathname)

			def rc = defaultSession.execute(cl)
			log.info "--> Unzipping [ END ]   (rc = ${rc})"
		}
		return defaultSession
	}

	/**
	 * ARF
	 * @param engine
	 * @return
	 */
	def generateResults(def engine) {
		def reportPrefix = engine.generateReportPrefix()

		def timestamp    = new Date().format("yyyyMMdd'T'HHmmss'Z'")
		def reportName   = "${reportPrefix}-${timestamp}"
		def statusWriter = engine.selectedDatastream.selectedChecklist.statusWriter

		def assessmentResults = engine.getOutputReport()

		statusWriter.writeStatus " ***** Writing Assessment Results ***** "

		def reportsDir = new File("${System.getProperty("user.dir")}\\reports")

		// Always generate the ARF/OVAL-Results XML file.
		def filepath = "${reportsDir.canonicalPath}${File.separator}${reportName}.xml"
		// For now this seems prettier than the XmlNodePrinter
		new File(filepath).withWriter { w ->
			w.write(XmlUtil.serialize(assessmentResults))
		}
		statusWriter.writeStatus " - Assessment Results saved to ${filepath}"

		// POST the results...
//		if (assessmentConfig.u) {
//			// "https://ec2-54-209-62-7.compute-1.amazonaws.com/CCPD/api/reports/upload"
//			def ru =
//				new ReportUploader(
//					url: assessmentConfig.u,
//					reportName: "${reportName}.xml",
//					reportContent: assessmentResults,
//					ignoreCertificateWarnings: (assessmentConfig.ui),
//					statusWriter: statusWriter).post()
//		}
	}

	/**
	 * Determine the element name in case a namespace prefix is applied.
	 * For example, the basename of element <oval-sc:registry_item> is "registry_item"
	 *
	 * @param elementName
	 * @return the basename w/out the namespace prefix, if there is one
	 */
	def getElementBasename(String elementName) {
		def basename = elementName
		def pos = elementName.indexOf(":")
		if (pos >= 0) {
			basename = elementName.substring(pos + 1)
		}
		return basename
	}
}

class ItemEventCoordinator implements ItemEventListener {
	@Override
	void handlePublishedItems(ItemPublishEvent items) {
		items.items.each { item ->
			log.info "Item --> ${item}"
		}
	}
}