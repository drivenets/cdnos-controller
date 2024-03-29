#!/usr/bin/groovy
@Library('jenkins-pipeline-shared@master') _


pipeline {
    agent {
        label 'kne'
    }
    stages {
        stage('Clean Workspace') {
            steps {
                script {
                    try {
                        sh "make kind-delete"
                    } catch (err) {
                        echo "Error cleaning workspace: ${err}"
                    }
                }
            }
        }
        stage('Build Controller Image') {
            steps {
                sh 'make docker-build'
            }
        }
        stage('Test on Kind Cluster') {
            steps{
                sh 'make kind'
            }
        }
        stage('Generate Manifest') {
            steps {
                sh 'make generate-manifest'
            }
        }
        stage ('Push Controller Image to Registry') {
            when {
                branch 'main'
            }
            steps {
                sh 'make docker-push'
            }
        }
    }
    post {
        success {
            archiveArtifacts artifacts: 'config/manifests/manifest.yaml', fingerprint: true
        }
        failure {
            sh "make kind-delete"
            cleanWs()
        }
    }
}