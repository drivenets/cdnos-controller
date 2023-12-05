#!/usr/bin/groovy
@Library('jenkins-pipeline-shared@master') _

pipeline{
    agent{
        label "kne"
    }
    stages{
        stage("A"){
            steps{
                echo "========executing A========"
                sh "ls -ltr"
            }
        }
    }
    post{
        success{
            echo "========pipeline executed successfully ========"
        }
        failure{
            echo "========pipeline execution failed========"
        }
        always{
            echo "========always========"
            cleanWs()
        }
    }
}