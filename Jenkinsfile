pipeline{

	agent {label 'auth.valuestory-dev'}

	environment {
	containerName = 'auth.valuestory.api'
        imageName    = 'auth.valuestory.api.dev'
	}
	stages {

		stage('Remove') {
			steps { 
				sh 'docker stop $containerName || true && docker rm -f $containerName || true'
			}
		}
		stage('Build') {
			steps {
				sh 'docker build -t $imageName .'
			}
		}
		stage('Deploy') {
			steps {
				sh 'docker run -e REDISHost=$REDISHost -e REDISPassword=$REDISPassword -e MYSQLHost=$MYSQLHost -e MYSQLPassword=$MYSQLPassword -e AccessSecretToken=$AccessSecretToken -e AuthUIDomain=$AuthUIDomain  -p 8080:8080 -d --name $containerName $imageName'
			}
		}

	}

}
