#!/bin/bash

#Get configuration details
CONFIGFILE=configuration
source $CONFIGFILE

TIME_FORMAT='%Y%m%d'
cTime=$(date +"${TIME_FORMAT}")
LOGFILENAME=$LOG_PATH/backup-${cTime}.log
CREDENTIALS="--defaults-extra-file=$MYSQL_CRE"

[ ! -d $LOG_PATH ] && ${MKDIR} -p ${LOG_PATH}
echo "" > ${LOGFILENAME}
echo "<<<<<<   Database Dump Report :: `date +%D`  >>>>>>" >> ${LOGFILENAME}
echo "" >> ${LOGFILENAME}
echo "DB Name  :: DB Size   Filename" >> ${LOGFILENAME}

#Check configuration file is existed
check_config(){
        [ ! -f $CONFIGFILE ] && close_on_error "Config file not found, make sure config file is correct"
}

db_backup(){
        FILEPATH="${LOCAL_BACKUP_DIR}/${cTime}/"
        if [ ! -d "${FILEPATH}" ]; then
                $MKDIR -p ${FILEPATH}
        fi

        for database in "${DB_NAMES[@]}"
        do
        FILENAME="${database}_${cTime}.gz"
        BACKUPFILE="$FILEPATH$FILENAME"
        if [ ! -f "${BACKUPFILE}" ]; then
                #Prevent database is being written while perform backup 
                $MYSQL ${CREDENTIALS} -Ae"FLUSH TABLES WITH READ LOCK;"
                $SLEEP 5
                #Backup file then compress it
                $MYSQLDUMP ${CREDENTIALS} --single-transaction --host=$MYSQL_HOST --port=$MYSQL_PORT "$database" | ${GZIP} -9 > $BACKUPFILE

                #Enable database to be written in
                $MYSQL ${CREDENTIALS} -Ae"UNLOCK TABLES;"

                #Write to log file
                echo "$database   :: `du -sh ${BACKUPFILE}`"  >> ${LOGFILENAME}
        fi

        #Delete backup file that is more than 30 days old
        #$FIND "$path" -type f -mtime +30 -delete
done

}

close_on_error(){
        echo "$@"
        exit 99
}

check_commands(){
        [ ! -x $GZIP ] && close_on_error "Executable $GZIP not found."
        [ ! -x $MYSQL ] && close_on_error "Executable $MYSQL not found."
        [ ! -x $MYSQLDUMP ] && close_on_error "Executable $MYSQLDUMP not found."
        [ ! -x $MKDIR ] && close_on_error "Executable $MKDIR not found."
        [ ! -x $GREP ] && close_on_error "Executable $GREP not found."
        [ ! -x $SLEEP ] && close_on_error "Executalbe $SLEEP not found."
        [ ! -x $FIND ] && close_on_error "Executable $FIND not found."
        [ ! -x $MYSQLADMIN ] && close_on_error "Executable $MYSQLADMIN not found."
}

check_mysql_connection(){
        # Check if MySQL server is alive
        $MYSQLADMIN ${CREDENTIALS} --host=${MYSQL_HOST} --port=${MYSQL_PORT} ping | ${GREP} 'alive'>/dev/null
        [ $? -eq 0 ] || close_on_error "Cannot connect to MySQL Server. Make sure username and password setup correctly in $CONFIGFILE"
}

sftp_backup(){
        cd $FILEPATH
        ${SCP} -P ${SFTP_PORT}  "$FILE_NAME" ${SFTP_USERNAME}@${SFTP_HOST}:${SFTP_UPLOAD_DIR}/
}

#main
check_config
check_commands
check_mysql_connection
db_backup