resource "aws_iam_user" "object_encryptor" {
  name = "${var.name_prefix}-object-encryptor"
}

resource "aws_iam_access_key" "object_encryptor" {
  user = aws_iam_user.object_encryptor.name
}

data "aws_iam_policy_document" "kms_access" {
  statement {
    sid = "UseKMSKeys"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = [
      aws_kms_key.object_encryptor.arn,
    ]
  }
}

resource "aws_iam_user_policy" "object_encryptor_tests" {
  user        = aws_iam_user.object_encryptor.name
  name_prefix = "kms-access-"
  policy      = data.aws_iam_policy_document.kms_access.json
}

output "aws_access_key_id" {
  value = aws_iam_access_key.object_encryptor.id
}

output "aws_access_key_secret" {
  value     = aws_iam_access_key.object_encryptor.secret
  sensitive = true
}
