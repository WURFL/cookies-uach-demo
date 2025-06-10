# cookies-uach-demo
Perform device detection on cookies containing User-Agent Client Hints (UACH) using the WURFL API

This demo accompanies a series of blog posts regarding making User-Agent Client Hint Data available in CDN logs and performing device detection using this saved data. This program takes a cookie string (containing lengthbin-encoded UACH), decodes it and performs device detection using the WURFL InFuze API for Golang.

## Requirements

* Golang v1.7 or higher
* [WURFL InFuze API for Golang](https://scientiamobile.com/wurfl-infuze/wurfl-infuze-module-for-golang/) license
* [libwurfl](https://docs.scientiamobile.com/documentation/infuze/infuze-c-api-user-guide) v1.13.3.0 or higher
* A [WURFL download key](https://docs.scientiamobile.com/guides/wurfl-snapshot-generator) (or alternatively a previously downloaded WURFL snapshot)

Full documentation for the WURFL InFuze API for Golang is available [here](https://docs.scientiamobile.com/documentation/infuze/infuze-golang-module-user-guide).

## Usage

Prior to running the demo, please replace the placeholder WURFL download key (`xxxxxxx`) with your actual key in `main.go`. If you prefer to use a previously downloaded WURFL snapshot, please make the appropriate changes to the WURFL Engine configuration.