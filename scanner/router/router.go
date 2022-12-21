package router

import (
	vulnerability_db_update "github.com/deepfence/package-scanner/scanner/controller/vulnerability-db-update"
	vulnerability_scan_service "github.com/deepfence/package-scanner/scanner/controller/vulnerability-scan-service"

	"github.com/gin-gonic/gin"
)

var (
	vulnerabilityScanController     = vulnerability_scan_service.New()
	VulnerabilityDBUpdateController = vulnerability_db_update.New()
)

// New instantiates a new gin router to handle API requests
func New() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	registerAllEndpoints(router)

	return router
}

// registerAllEndpoints registers all of the endpoints supported by the server
func registerAllEndpoints(r *gin.Engine) {

	// registers the below endpoints
	addPingRoutes(r)
	addVulnerabilityService(r)
	addDBUpdateService(r)
}
