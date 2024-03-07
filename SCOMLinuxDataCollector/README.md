# SCOM Linux Data Collector

[https://aka.ms/SCOM-LinuxDataCollector](https://aka.ms/SCOM-LinuxDataCollector)

- The SCOM Linux Data Collector is a shell script which can be run on Linux/Unix Distribution to collect information about the Operating System and the SCOM Linux Agent.
- This tool can be helpful to figure out problems one might encounter during SCOM Linux Agent Installation and Monitoring.
- The tool is Read-Only and does not change the state of the executed machine.

| Parameters | Purpose               | Description                                                                                                      |
|------------|-----------------------|------------------------------------------------------------------------------------------------------------------|
| -o         | OutputPath            | Specify the location of collection. If not specified, it will collect the data in the current working directory. |
| -m         | SCXMaintenanceAccount | Specify the SCX Maintenance Account. This will be used to check the sudo privilege for the account.              |
| -n         | SCXMonitoringAccount  | Specify the SCX Monitoring Account. This will be used to check the sudo privilege for the account.               |

## Usage
```bash
~\# bash SCOMLinuxDataCollector.sh -o [output directory] -m [scom maintenance account] -n [scom monitoring account]
```

### Example
```bash
~\# bash SCOMLinuxDataCollector.sh -o /tmp -m scxmaint -n scxmon
```

## Output
The output will be a zipped file with the name `SCOMLinuxDataCollectorData.tar.gz`
