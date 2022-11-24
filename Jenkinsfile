pipeline{

	agent {label 'docker-test'}

	environment {
	containerName = 'auth.valuestory.api.dev'
        imageName    = 'auth.valuestory.api'
	}
	stages {

		stage('Kill') {
			steps {
				sh 'docker stop $(docker ps -a -q)' 
			}
		}
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
				sh 'docker run -p 8081:8080 -d --name $containerName $imageName'
			}
		}

	}

}