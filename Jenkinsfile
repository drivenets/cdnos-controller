#!/usr/bin/groovy
@Library('jenkins-pipeline-shared@master') _

pipeline {
    agent {
        label "kne"
    }
    stages {
        stage("A") {
            steps{
                echo "========executing A========"
                sh "ls -ltr"
                sh "kne version"
            }
        }
    }
    post {
        cleanup {
            echo "========always========"
            cleanWs()
        }
    }
}