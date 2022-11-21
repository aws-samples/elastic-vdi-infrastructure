import aws_cdk as core
import aws_cdk.assertions as assertions

from elastic_vdi_infrastructure.elastic_vdi_infrastructure_stack import ElasticVdiInfrastructureStack

# example tests. To run these tests, uncomment this file along with the example
# resource in elastic_vdi_infrastructure/elastic_vdi_infrastructure_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = ElasticVdiInfrastructureStack(app, "elastic-vdi-infrastructure")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
