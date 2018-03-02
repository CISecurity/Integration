package org.cisecurity.ietf.sacm

import com.xebialabs.overthere.CmdLine
import groovy.xml.XmlUtil
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
import org.slf4j.LoggerFactory

/**
 * Perform the assessments.
 *
 * Created by wmunyan on 2/26/2018.
 */
class AssessmentWrapper {
	def log = LoggerFactory.getLogger(AssessmentWrapper.class)

	ResultsPublisher pub

	/**
	 * Perform the assessments.
	 *
	 * @param assessorQueue
	 * @return
	 */
	def execute(def assessorQueue = []) {
		def assessmentResults = []

		if (assessorQueue.size() > 0) {
			def session = initializeDefaultSession()

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

					//collectInteractiveValues(checklistEngine)

					engine.session = session
					checklistEngine.session = session
					checklistEngine.statusWriter = statusWriter
					checklistEngine.checklistProperties = AssessorUtilities.instance.userProperties
					checklistEngine.transform()
					checklistEngine.evaluate()

					assessmentResults << generateResults(engine)
				}
			}
			session.disconnect()

		} else {
			log.info "No valid payloads were retrieved from the node."
		}

		pub.publish(assessmentResults)
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

		statusWriter.writeStatus " ***** Generating Assessment Results ***** "
		def assessmentResults = engine.getOutputReport()



		def reportsDir = new File("${System.getProperty("user.dir")}\\reports")

		// Always generate the ARF/OVAL-Results XML file.
		def filepath = "${reportsDir.canonicalPath}${File.separator}${reportName}.xml"
		// For now this seems prettier than the XmlNodePrinter
		new File(filepath).withWriter { w ->
			w.write(XmlUtil.serialize(assessmentResults))
		}
		statusWriter.writeStatus " - Assessment Results saved to ${filepath}"

		return filepath

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
}
