#!/usr/bin/groovy
@Library('jenkins-pipeline-shared@master') _

pipeline {
    agent {
        label "kne"
    }
    stages {
        stage("Deployment") {
            steps{
                sh "make docker-build"
                sh "make install"
                sh "make deploy"
                sh "kubectl apply -k config/samples/"
                sh "kubectl get cdnos"
            }
        }
        stage("Generate Manifest") {
            steps{
                sh "make generate-manifest"
            }
        }
    }
    post {
        success {
            archiveArtifacts artifacts: 'config/manifests/manifest.yaml', fingerprint: true
        }
        cleanup {
            echo "========always========"
            sh "kubectl delete -k config/samples/"
            sh "make undeploy"
            cleanWs()
        }
    }
}