from .base_check import BaseCheck
from typing import List, Dict
import ipaddress
from datetime import datetime
import json
import socket
import csv
import io

class SecurityGroupRemoteAccessCheck(BaseCheck):
    async def check(self) -> List[Dict]:
        ec2 = self.session.client('ec2')
        results = []
        raw = []
        
        try:
            security_groups = ec2.describe_security_groups()
            
            if not security_groups['SecurityGroups']:
                results.append(self.get_result(
                    'PASS', 'N/A',
                    "Security Group이 존재하지 않습니다."
                ))
                return {'results': results, 'raw': raw, 'guideline_id': 5}
            
            for sg in security_groups['SecurityGroups']:
                sg_id = sg['GroupId']
                sg_name = sg.get('GroupName', 'N/A')
                inbound_rules = sg.get('IpPermissions', [])
                
                sg_has_violation = False
                violations = []
                
                for rule in inbound_rules: # raw 데이터 수집 전에 미리 raw에 추가하려면 수정 필요
                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')
                    
                    # SSH(22) 또는 RDP(3389) 포트인지 확인
                    if from_port is None or to_port is None:
                        continue
                    
                    is_target_port = (from_port <= 22 <= to_port) or (from_port <= 3389 <= to_port)
                    
                    if not is_target_port:
                        continue
                    
                    # IPv4 CIDR 검사
                    ipv4_ranges = rule.get('IpRanges', [])
                    for cidr_range in ipv4_ranges:
                        cidr = cidr_range.get('CidrIp')
                        description = cidr_range.get('Description', '')
                        
                        try:
                            network = ipaddress.IPv4Network(cidr, strict=False)
                            # /16보다 넓으면 (prefixlen < 16) FAIL
                            if network.prefixlen < 16:
                                sg_has_violation = True
                                violations.append({
                                    'port': f"{from_port}-{to_port}",
                                    'cidr': cidr,
                                    'prefix_len': network.prefixlen,
                                    'description': description
                                })
                        except ValueError:
                            pass
                    
                    # IPv6 CIDR 검사
                    ipv6_ranges = rule.get('Ipv6Ranges', [])
                    for cidr_range in ipv6_ranges:
                        cidr = cidr_range.get('CidrIpv6')
                        description = cidr_range.get('Description', '')
                        
                        try:
                            network = ipaddress.IPv6Network(cidr, strict=False)
                            # /32보다 넓으면 (prefixlen < 32) FAIL
                            if network.prefixlen < 32:
                                sg_has_violation = True
                                violations.append({
                                    'port': f"{from_port}-{to_port}",
                                    'cidr': cidr,
                                    'prefix_len': network.prefixlen,
                                    'description': description
                                })
                        except ValueError:
                            pass
                
                raw.append({
                    'sg_id': sg_id,
                    'sg_name': sg_name,
                    'inbound_rules': inbound_rules,
                    'violations': violations,
                    'sg_data': sg
                })
                
                if sg_has_violation:
                    results.append(self.get_result(
                        'FAIL', sg_id,
                        f"Security Group {sg_name}({sg_id})에 SSH 또는 RDP 포트가 /16보다 넓은 CIDR로 열려있습니다.",
                        {
                            'sg_name': sg_name,
                            'violations': violations
                        }
                    ))
                else:
                    results.append(self.get_result(
                        'PASS', sg_id,
                        f"Security Group {sg_name}({sg_id})는 SSH/RDP 포트가 안전하게 구성되어 있습니다.",
                        {
                            'sg_name': sg_name,
                            'inbound_rules': inbound_rules
                        }
                    ))
        
        except Exception as e:
            results.append(self.get_result('ERROR', 'N/A', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 5}

class IAMAccessKeyAgeCheck(BaseCheck):
    async def check(self) -> List[Dict]:
        iam = self.session.client('iam')
        results = []
        raw = []
        
        try:
            users = iam.list_users()['Users']
            
            for user in users:
                username = user['UserName']
                access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
                
                for key in access_keys:
                    key_age = (datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']).days
                    access_key_id = key['AccessKeyId']
                    
                    raw.append({
                        'username': username,
                        'access_key_id': access_key_id,
                        'key_age_days': key_age,
                        'create_date': key['CreateDate'],
                        'status': key['Status'],
                        'key_data': key
                    })
                    
                    if key_age > 90:
                        results.append(self.get_result(
                            'FAIL',
                            access_key_id,
                            f"사용자 {username}의 액세스 키가 {key_age}일 이상 사용되고 있습니다. 90일 이내에 교체하세요.",
                            {
                                'username': username,
                                'age_days': key_age,
                                'status': key['Status']
                            }
                        ))
                    else:
                        results.append(self.get_result(
                            'PASS',
                            access_key_id,
                            f"사용자 {username}의 액세스 키는 {key_age}일 전에 생성되었습니다.",
                            {
                                'username': username,
                                'age_days': key_age,
                                'status': key['Status']
                            }
                        ))
        except Exception as e:
            results.append(self.get_result('ERROR', 'N/A', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 13}

class IAMRootAccessKeyCheck(BaseCheck):
    async def check(self) -> List[Dict]:
        iam = self.session.client('iam')
        results = []
        raw = []
        
        try:
            summary = iam.get_account_summary()['SummaryMap']
            root_keys = summary.get('AccountAccessKeysPresent', 0)
            
            raw.append({
                'account_type': 'root',
                'access_keys_present': root_keys,
                'account_summary': summary
            })
            
            if root_keys > 0:
                results.append(self.get_result(
                    'FAIL', 'root',
                    f"Root 계정에 {root_keys}개의 액세스 키가 있습니다. 보안상 Root 계정의 액세스 키는 삭제해야 합니다.",
                    {
                        'key_count': root_keys,
                        'account_type': 'root'
                    }
                ))
            else:
                results.append(self.get_result(
                    'PASS', 'root',
                    "Root 계정에 액세스 키가 없습니다."
                ))
        except Exception as e:
            results.append(self.get_result('ERROR', 'root', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 15}

class IAMMFACheck(BaseCheck):
    async def check(self) -> List[Dict]:
        iam = self.session.client('iam')
        results = []
        raw = []
        
        try:
            # Root 계정 MFA 확인
            summary = iam.get_account_summary()['SummaryMap']
            root_mfa_enabled = summary.get('AccountMFAEnabled', 0)
            
            # 모든 IAM 사용자 조회
            users_response = iam.list_users()
            users = users_response.get('Users', [])
            
            users_without_mfa = []
            users_with_mfa = []
            
            # 각 사용자의 MFA 확인
            for user in users:
                user_name = user.get('UserName')
                
                try:
                    mfa_devices = iam.list_mfa_devices(UserName=user_name)
                    mfa_device_list = mfa_devices.get('MFADevices', [])
                    
                    if mfa_device_list:
                        users_with_mfa.append({
                            'user_name': user_name,
                            'mfa_device_count': len(mfa_device_list)
                        })
                    else:
                        users_without_mfa.append(user_name)
                except:
                    users_without_mfa.append(user_name)
            
            raw.append({
                'root_mfa_enabled': root_mfa_enabled == 1,
                'total_users': len(users),
                'users_with_mfa': users_with_mfa,
                'users_without_mfa': users_without_mfa,
                'account_summary': summary
            })
            
            # Root 계정 MFA 미활성화
            if root_mfa_enabled == 0:
                results.append(self.get_result(
                    'FAIL', 'root',
                    "Root 계정에 MFA가 활성화되지 않았습니다.",
                    {
                        'mfa_enabled': False,
                        'account_type': 'root'
                    }
                ))
            else:
                results.append(self.get_result(
                    'PASS', 'root',
                    "Root 계정에 MFA가 활성화되어 있습니다.",
                    {
                        'mfa_enabled': True,
                        'account_type': 'root'
                    }
                ))
            
            # IAM 사용자 MFA 확인
            if users_without_mfa:
                results.append(self.get_result(
                    'FAIL', 'iam_users',
                    f"다음 IAM 사용자에 MFA가 설정되지 않았습니다: {', '.join(users_without_mfa)}",
                    {
                        'users_without_mfa': users_without_mfa,
                        'users_with_mfa_count': len(users_with_mfa),
                        'users_without_mfa_count': len(users_without_mfa)
                    }
                ))
            elif len(users) > 0:
                results.append(self.get_result(
                    'PASS', 'iam_users',
                    f"모든 IAM 사용자에 MFA가 설정되어 있습니다.",
                    {
                        'users_with_mfa_count': len(users_with_mfa),
                        'total_users': len(users)
                    }
                ))
            
        except Exception as e:
            results.append(self.get_result('ERROR', 'N/A', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 16}
class RDSSnapshotPublicAccessCheck(BaseCheck):
    async def check(self) -> List[Dict]:
        rds = self.session.client('rds')
        results = []
        raw = []
        
        try:
            # DB 스냅샷 조회
            db_snapshots = rds.describe_db_snapshots()
            
            manual_db_snapshots = [s for s in db_snapshots['DBSnapshots'] if s.get('SnapshotType') == 'manual']
            
            if not manual_db_snapshots:
                results.append(self.get_result(
                    'PASS', 'N/A',
                    "이 리전에서 관리 중인 RDS 수동 DB 스냅샷이 없습니다."
                ))
            else:
                for snapshot in manual_db_snapshots:
                    snapshot_id = snapshot['DBSnapshotIdentifier']
                    snapshot_type = snapshot.get('SnapshotType', 'N/A')
                    
                    # 스냅샷 속성 조회
                    try:
                        attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snapshot_id)
                        restore_attributes = attrs.get('DBSnapshotAttributesResult', {}).get('DBSnapshotAttributes', [])
                        is_public = any(attr.get('AttributeName') == 'restore' and 'all' in attr.get('AttributeValues', []) for attr in restore_attributes)
                    except:
                        is_public = False
                    
                    raw.append({
                        'snapshot_id': snapshot_id,
                        'snapshot_type': snapshot_type,
                        'is_public': is_public,
                        'snapshot_data': snapshot
                    })
                    
                    if is_public:
                        results.append(self.get_result(
                            'FAIL', snapshot_id,
                            f"RDS DB 스냅샷 {snapshot_id}이 공개로 설정되어 있습니다.",
                            {
                                'snapshot_id': snapshot_id,
                                'is_public': is_public,
                                'snapshot_type': snapshot_type
                            }
                        ))
                    else:
                        results.append(self.get_result(
                            'PASS', snapshot_id,
                            f"RDS DB 스냅샷 {snapshot_id}은 프라이빗으로 설정되어 있습니다.",
                            {
                                'snapshot_id': snapshot_id,
                                'is_public': is_public,
                                'snapshot_type': snapshot_type
                            }
                        ))
            
            # DB 클러스터 스냅샷 조회
            cluster_snapshots = rds.describe_db_cluster_snapshots()
            
            manual_cluster_snapshots = [s for s in cluster_snapshots['DBClusterSnapshots'] if s.get('SnapshotType') == 'manual']
            
            if manual_cluster_snapshots:
                for snapshot in manual_cluster_snapshots:
                    snapshot_id = snapshot['DBClusterSnapshotIdentifier']
                    snapshot_type = snapshot.get('SnapshotType', 'N/A')
                    
                    # 클러스터 스냅샷 속성 조회
                    try:
                        attrs = rds.describe_db_cluster_snapshot_attributes(DBClusterSnapshotIdentifier=snapshot_id)
                        restore_attributes = attrs.get('DBClusterSnapshotAttributesResult', {}).get('DBClusterSnapshotAttributes', [])
                        is_public = any(attr.get('AttributeName') == 'restore' and 'all' in attr.get('AttributeValues', []) for attr in restore_attributes)
                    except:
                        is_public = False
                    
                    raw.append({
                        'snapshot_id': snapshot_id,
                        'snapshot_type': snapshot_type,
                        'is_public': is_public,
                        'snapshot_data': snapshot
                    })
                    
                    if is_public:
                        results.append(self.get_result(
                            'FAIL', snapshot_id,
                            f"RDS 클러스터 스냅샷 {snapshot_id}이 공개로 설정되어 있습니다.",
                            {
                                'snapshot_id': snapshot_id,
                                'is_public': is_public,
                                'snapshot_type': snapshot_type
                            }
                        ))
                    else:
                        results.append(self.get_result(
                            'PASS', snapshot_id,
                            f"RDS 클러스터 스냅샷 {snapshot_id}은 프라이빗으로 설정되어 있습니다.",
                            {
                                'snapshot_id': snapshot_id,
                                'is_public': is_public,
                                'snapshot_type': snapshot_type
                            }
                        ))
        
        except Exception as e:
            results.append(self.get_result('ERROR', 'N/A', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 27}

class CloudTrailLoggingCheck(BaseCheck):
    async def check(self) -> List[Dict]:
        cloudtrail = self.session.client('cloudtrail')
        results = []
        raw = []
        
        try:
            trails = cloudtrail.describe_trails()
            
            if not trails['trailList']:
                results.append(self.get_result(
                    'FAIL', 'N/A',
                    "CloudTrail 추적이 없습니다."
                ))
                return {'results': results, 'raw': raw, 'guideline_id': 30}
            
            for trail in trails['trailList']:
                trail_name = trail.get('Name')
                trail_arn = trail.get('TrailARN')
                trail_status = cloudtrail.get_trail_status(Name=trail_name)
                is_logging = trail_status.get('IsLogging', False)
                
                # 추적 설정
                is_multi_region = trail.get('IsMultiRegionTrail', False)
                is_organization_trail = trail.get('IsOrganizationTrail', False)
                
                raw.append({
                    'trail_name': trail_name,
                    'trail_arn': trail_arn,
                    'is_logging': is_logging,
                    'is_multi_region': is_multi_region,
                    'is_organization_trail': is_organization_trail,
                    'trail_data': trail,
                    'trail_status': trail_status
                })
                
                if not is_logging:
                    results.append(self.get_result(
                        'FAIL', trail_name,
                        f"CloudTrail 추적 {trail_name}은 로깅이 비활성화되어 있습니다.",
                        {
                            'trail_name': trail_name,
                            'is_logging': is_logging,
                            'is_organization_trail': is_organization_trail
                        }
                    ))
                else:
                    results.append(self.get_result(
                        'PASS', trail_name,
                        f"CloudTrail 추적 {trail_name}은 로깅이 활성화되어 있습니다.",
                        {
                            'trail_name': trail_name,
                            'is_logging': is_logging,
                            'is_organization_trail': is_organization_trail
                        }
                    ))
        
        except Exception as e:
            results.append(self.get_result('ERROR', 'N/A', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 30}

class SNSTopicAccessPolicyCheck(BaseCheck):
    async def check(self) -> List[Dict]:
        sns = self.session.client('sns')
        results = []
        raw = []
        
        try:
            topics = sns.list_topics()
            
            if not topics.get('Topics'):
                results.append(self.get_result(
                    'PASS', 'N/A',
                    "SNS 주제가 없습니다."
                ))
                return {'results': results, 'raw': raw, 'guideline_id': 38}
            
            for topic in topics['Topics']:
                topic_arn = topic['TopicArn']
                topic_name = topic_arn.split(':')[-1]
                
                try:
                    # 주제 정책 조회
                    policy_response = sns.get_topic_attributes(
                        TopicArn=topic_arn
                    )
                    
                    policy_str = policy_response.get('Attributes', {}).get('Policy')
                    if not policy_str:
                        results.append(self.get_result(
                            'PASS', topic_name,
                            f"SNS 주제 {topic_name}에 정책이 없습니다.",
                            {
                                'topic_arn': topic_arn,
                                'has_policy': False
                            }
                        ))
                        raw.append({
                            'topic_arn': topic_arn,
                            'topic_name': topic_name,
                            'has_policy': False,
                            'policy': None
                        })
                        continue
                    
                    policy = json.loads(policy_str)
                    statements = policy.get('Statement', [])
                    
                    is_properly_restricted = True
                    violation_reasons = []
                    
                    for statement in statements:
                        # Allow 문장만 검사
                        if statement.get('Effect') != 'Allow':
                            continue
                        
                        # Principal 검사
                        principal = statement.get('Principal', {})
                        has_restricted_principal = self._is_principal_restricted(principal)
                        
                        # Resource 검사
                        resource = statement.get('Resource', [])
                        if isinstance(resource, str):
                            resource = [resource]
                        has_restricted_resource = all(r == topic_arn or r == '*' for r in resource)
                        
                        # SNS 관련 권한 검사
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        has_sns_permission = any(
                            action.lower().startswith('sns:') 
                            for action in actions
                        )
                        
                        # Principal이 "*"이거나 특정 계정/역할/사용자로 제한되지 않으면 FAIL
                        if has_sns_permission and (not has_restricted_principal or principal.get('AWS') == '*'):
                            is_properly_restricted = False
                            violation_reasons.append("Principal이 제한되지 않음 또는 와일드카드 사용")
                        
                        # Resource가 해당 주제의 ARN이 아니거나 "*"이면 FAIL
                        if has_sns_permission and not has_restricted_resource:
                            is_properly_restricted = False
                            violation_reasons.append("Resource가 해당 주제 ARN으로 제한되지 않음")
                    
                    raw.append({
                        'topic_arn': topic_arn,
                        'topic_name': topic_name,
                        'has_policy': True,
                        'policy': policy,
                        'is_properly_restricted': is_properly_restricted,
                        'violation_reasons': violation_reasons
                    })
                    
                    if is_properly_restricted:
                        results.append(self.get_result(
                            'PASS', topic_name,
                            f"SNS 주제 {topic_name}의 액세스 정책은 적절하게 제한되어 있습니다.",
                            {
                                'topic_arn': topic_arn,
                                'is_properly_restricted': True
                            }
                        ))
                    else:
                        results.append(self.get_result(
                            'FAIL', topic_name,
                            f"SNS 주제 {topic_name}의 액세스 정책이 과도하게 개방되어 있습니다: {', '.join(violation_reasons)}",
                            {
                                'topic_arn': topic_arn,
                                'is_properly_restricted': False,
                                'violation_reasons': violation_reasons
                            }
                        ))
                
                except Exception as e:
                    results.append(self.get_result(
                        'ERROR', topic_name,
                        f"주제 {topic_name} 정책 조회 중 오류: {str(e)}"
                    ))
        
        except Exception as e:
            results.append(self.get_result('ERROR', 'N/A', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 38}
    
    def _is_principal_restricted(self, principal: Dict) -> bool:
        """Principal이 특정 계정/역할/사용자로 제한되어 있는지 확인"""
        if not principal:
            return False
        
        # Principal이 AWS 키를 가지고 있는지 확인
        if 'AWS' in principal:
            aws_principal = principal['AWS']
            
            # 문자열인 경우
            if isinstance(aws_principal, str):
                # "*"이거나 와일드카드가 포함되면 제한되지 않음
                if aws_principal == '*' or '*' in aws_principal:
                    return False
                # ARN 형식이면 제한됨 (계정, 역할, 사용자)
                if aws_principal.startswith('arn:aws:'):
                    return True
            
            # 리스트인 경우
            elif isinstance(aws_principal, list):
                # 모든 항목이 "*" 또는 와일드카드가 아니어야 함
                for p in aws_principal:
                    if p == '*' or (isinstance(p, str) and '*' in p):
                        return False
                # 모든 항목이 ARN 형식이면 제한됨
                if all(isinstance(p, str) and p.startswith('arn:aws:') for p in aws_principal):
                    return True
        
        return False

class ECRRepositorySecurityCheck(BaseCheck):
    async def check(self) -> List[Dict]:
        ecr = self.session.client('ecr')
        results = []
        raw = []
        
        try:
            repositories = ecr.describe_repositories()
            
            if not repositories.get('repositories'):
                results.append(self.get_result(
                    'PASS', 'N/A',
                    "ECR 리포지토리가 없습니다."
                ))
                return {'results': results, 'raw': raw, 'guideline_id': 43}
            
            for repo in repositories['repositories']:
                repo_name = repo.get('repositoryName')
                repo_arn = repo.get('repositoryArn')
                
                # 리포지토리 정책 조회
                policy_str = None
                try:
                    policy_response = ecr.get_repository_policy(repositoryName=repo_name)
                    policy_str = policy_response.get('repositoryPolicy')
                except ecr.exceptions.RepositoryPolicyNotFoundException:
                    policy_str = None
                
                # 이미지 스캔 활성화 여부
                image_scan_enabled = repo.get('imageScanningConfiguration', {}).get('scanOnPush', False)
                
                # 태그 불변 여부
                image_tag_mutability = repo.get('imageTagMutability', 'MUTABLE')
                tag_immutable_enabled = image_tag_mutability == 'IMMUTABLE'
                
                violations = []
                
                # 정책 검사
                if policy_str:
                    policy = json.loads(policy_str)
                    statements = policy.get('Statement', [])
                    
                    for statement in statements:
                        if statement.get('Effect') != 'Allow':
                            continue
                        
                        principal = statement.get('Principal', {})
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        # Principal이 "*"인지 확인
                        is_wildcard_principal = principal == '*' or principal.get('AWS') == '*' or principal.get('Service') == '*'
                        
                        # Push/Pull 권한 확인
                        push_actions = ['ecr:InitiateLayerUpload', 'ecr:UploadLayerPart', 'ecr:CompleteLayerUpload', 'ecr:PutImage', 'ecr:BatchCheckLayerAvailability']
                        pull_actions = ['ecr:GetDownloadUrlForLayer', 'ecr:BatchGetImage']
                        
                        has_push = any(action in actions or action == 'ecr:*' or action == '*' for action in push_actions)
                        has_pull = any(action in actions or action == 'ecr:*' or action == '*' for action in pull_actions)
                        
                        # 와일드카드 주체 + Push/Pull 권한 확인
                        if is_wildcard_principal and (has_push or has_pull):
                            violations.append({
                                'type': '와일드카드 주체에 Push/Pull 권한 허용',
                                'principal': str(principal),
                                'has_push': has_push,
                                'has_pull': has_pull
                            })
                else:
                    # 정책이 없으면 기본적으로 제한됨
                    pass
                
                # 이미지 스캔 비활성화 확인
                if not image_scan_enabled:
                    violations.append({
                        'type': '이미지 스캔 비활성화'
                    })
                
                # 태그 불변 비활성화 확인
                if not tag_immutable_enabled:
                    violations.append({
                        'type': '태그 불변 비활성화'
                    })
                
                raw.append({
                    'repo_name': repo_name,
                    'repo_arn': repo_arn,
                    'policy': policy_str,
                    'image_scan_enabled': image_scan_enabled,
                    'tag_immutable_enabled': tag_immutable_enabled,
                    'violations': violations,
                    'repo_data': repo
                })
                
                if violations:
                    violation_messages = [v.get('type') for v in violations]
                    results.append(self.get_result(
                        'FAIL', repo_name,
                        f"ECR 리포지토리 {repo_name}에서 다음 보안 문제가 발견되었습니다: {', '.join(violation_messages)}",
                        {
                            'repo_name': repo_name,
                            'image_scan_enabled': image_scan_enabled,
                            'tag_immutable_enabled': tag_immutable_enabled,
                            'violations': violations
                        }
                    ))
                else:
                    results.append(self.get_result(
                        'PASS', repo_name,
                        f"ECR 리포지토리 {repo_name}은 보안 정책이 적절하게 구성되어 있습니다.",
                        {
                            'repo_name': repo_name,
                            'image_scan_enabled': image_scan_enabled,
                            'tag_immutable_enabled': tag_immutable_enabled
                        }
                    ))
        
        except Exception as e:
            results.append(self.get_result('ERROR', 'N/A', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 43}

class SSMDocumentPublicAccessCheck(BaseCheck):
    async def check(self) -> List[Dict]:
        ssm = self.session.client('ssm')
        results = []
        raw = []
        
        try:
            documents = ssm.list_documents(Filters=[{'Key': 'Owner', 'Values': ['Self']}])
            
            if not documents.get('DocumentIdentifiers'):
                results.append(self.get_result(
                    'PASS', 'N/A',
                    "소유한 SSM 문서가 없습니다."
                ))
                return {'results': results, 'raw': raw, 'guideline_id': 46}
            
            for doc in documents['DocumentIdentifiers']:
                doc_name = doc.get('Name')
                
                try:
                    # 문서 권한 조회
                    permissions = ssm.describe_document_permission(
                        Name=doc_name,
                        PermissionType='Share'
                    )
                    
                    account_ids = permissions.get('AccountIds', [])
                    is_public = 'all' in account_ids
                    
                    raw.append({
                        'document_name': doc_name,
                        'account_ids': account_ids,
                        'is_public': is_public,
                        'document_data': doc
                    })
                    
                    if is_public:
                        results.append(self.get_result(
                            'FAIL', doc_name,
                            f"SSM 문서 {doc_name}이 퍼블릭으로 공유되어 있습니다.",
                            {
                                'document_name': doc_name,
                                'is_public': True,
                                'account_ids': account_ids
                            }
                        ))
                    else:
                        results.append(self.get_result(
                            'PASS', doc_name,
                            f"SSM 문서 {doc_name}은 프라이빗으로 설정되어 있습니다.",
                            {
                                'document_name': doc_name,
                                'is_public': False,
                                'account_ids': account_ids
                            }
                        ))
                
                except Exception as e:
                    results.append(self.get_result('ERROR', doc_name, str(e)))
        
        except Exception as e:
            results.append(self.get_result('ERROR', 'N/A', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 46}

class OpenSearchVPCAccessCheck(BaseCheck):
    async def check(self) -> List[Dict]:
        opensearch = self.session.client('opensearch')
        results = []
        raw = []
        
        try:
            domains = opensearch.list_domain_names()
            
            if not domains.get('DomainNames'):
                results.append(self.get_result(
                    'PASS', 'N/A',
                    "OpenSearch 도메인이 없습니다."
                ))
                return {'results': results, 'raw': raw, 'guideline_id': 52}
            
            for domain_info in domains['DomainNames']:
                domain_name = domain_info.get('DomainName')
                
                try:
                    domain = opensearch.describe_domain(DomainName=domain_name)
                    domain_status = domain.get('DomainStatus', {})
                    
                    vpc_options = domain_status.get('VPCOptions', {})
                    vpc_id = vpc_options.get('VPCId')
                    
                    raw.append({
                        'domain_name': domain_name,
                        'vpc_id': vpc_id,
                        'vpc_options': vpc_options,
                        'domain_data': domain_status
                    })
                    
                    if vpc_id:
                        results.append(self.get_result(
                            'PASS', domain_name,
                            f"OpenSearch 도메인 {domain_name}은 VPC 액세스 전용으로 설정되어 있습니다.",
                            {
                                'domain_name': domain_name,
                                'vpc_id': vpc_id,
                                'subnet_ids': vpc_options.get('SubnetIds', [])
                            }
                        ))
                    else:
                        results.append(self.get_result(
                            'FAIL', domain_name,
                            f"OpenSearch 도메인 {domain_name}이 퍼블릭 엔드포인트로 설정되어 있습니다. | VPC 액세스 전용으로 설정하세요.",
                            {
                                'domain_name': domain_name,
                                'vpc_id': None
                            }
                        ))
                
                except Exception as e:
                    results.append(self.get_result('ERROR', domain_name, str(e)))
        
        except Exception as e:
            results.append(self.get_result('ERROR', 'N/A', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 52}

class RedshiftEncryptionCheck(BaseCheck):
    async def check(self) -> List[Dict]:
        redshift = self.session.client('redshift')
        results = []
        raw = []
        
        try:
            clusters = redshift.describe_clusters()
            
            if not clusters.get('Clusters'):
                results.append(self.get_result(
                    'PASS', 'N/A',
                    "Redshift 클러스터가 없습니다."
                ))
                return {'results': results, 'raw': raw, 'guideline_id': 55}
            
            for cluster in clusters['Clusters']:
                cluster_id = cluster.get('ClusterIdentifier')
                encrypted = cluster.get('Encrypted', False)
                
                raw.append({
                    'cluster_id': cluster_id,
                    'encrypted': encrypted,
                    'kms_key_id': cluster.get('KmsKeyId'),
                    'cluster_data': cluster
                })
                
                if encrypted:
                    results.append(self.get_result(
                        'PASS', cluster_id,
                        f"Redshift 클러스터 {cluster_id}는 암호화가 활성화되어 있습니다.",
                        {
                            'cluster_id': cluster_id,
                            'encrypted': True,
                            'kms_key_id': cluster.get('KmsKeyId')
                        }
                    ))
                else:
                    results.append(self.get_result(
                        'FAIL', cluster_id,
                        f"Redshift 클러스터 {cluster_id}의 암호화가 비활성화되어 있습니다. | 암호화를 활성화하세요.",
                        {
                            'cluster_id': cluster_id,
                            'encrypted': False
                        }
                    ))
        
        except Exception as e:
            results.append(self.get_result('ERROR', 'N/A', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 55}

class DocumentDBSnapshotPrivateCheck(BaseCheck):
    async def check(self) -> List[Dict]:
        docdb = self.session.client('docdb')
        results = []
        raw = []
        
        try:
            snapshots = docdb.describe_db_cluster_snapshots()
            
            if not snapshots.get('DBClusterSnapshots'):
                results.append(self.get_result(
                    'PASS', 'N/A',
                    "DocumentDB 스냅샷이 없습니다."
                ))
                return {'results': results, 'raw': raw, 'guideline_id': 59}
            
            for snapshot in snapshots['DBClusterSnapshots']:
                snapshot_id = snapshot.get('DBClusterSnapshotIdentifier')
                
                try:
                    attrs = docdb.describe_db_cluster_snapshot_attributes(
                        DBClusterSnapshotIdentifier=snapshot_id
                    )
                    
                    attributes = attrs.get('DBClusterSnapshotAttributesResult', {}).get('DBClusterSnapshotAttributes', [])
                    is_public = False
                    
                    for attr in attributes:
                        if attr.get('AttributeName') == 'restore':
                            values = attr.get('AttributeValues', [])
                            if 'all' in values:
                                is_public = True
                                break
                    
                    raw.append({
                        'snapshot_id': snapshot_id,
                        'is_public': is_public,
                        'attributes': attributes,
                        'snapshot_data': snapshot
                    })
                    
                    if is_public:
                        results.append(self.get_result(
                            'FAIL', snapshot_id,
                            f"DocumentDB 스냅샷 {snapshot_id}이 퍼블릭으로 공유되어 있습니다. | 프라이빗으로 설정하세요.",
                            {
                                'snapshot_id': snapshot_id,
                                'is_public': True
                            }
                        ))
                    else:
                        results.append(self.get_result(
                            'PASS', snapshot_id,
                            f"DocumentDB 스냅샷 {snapshot_id}은 프라이빗으로 설정되어 있습니다.",
                            {
                                'snapshot_id': snapshot_id,
                                'is_public': False
                            }
                        ))
                
                except Exception as e:
                    results.append(self.get_result('ERROR', snapshot_id, str(e)))
        
        except Exception as e:
            results.append(self.get_result('ERROR', 'N/A', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 59}

class DocumentDBEncryptionCheck(BaseCheck):
    async def check(self) -> List[Dict]:
        docdb = self.session.client('docdb')
        results = []
        raw = []
        
        try:
            clusters = docdb.describe_db_clusters()
            
            if not clusters.get('DBClusters'):
                results.append(self.get_result(
                    'PASS', 'N/A',
                    "DocumentDB 클러스터가 없습니다."
                ))
                return {'results': results, 'raw': raw, 'guideline_id': 60}
            
            for cluster in clusters['DBClusters']:
                cluster_id = cluster.get('DBClusterIdentifier')
                encrypted = cluster.get('StorageEncrypted', False)
                kms_key_id = cluster.get('KmsKeyId')
                
                raw.append({
                    'cluster_id': cluster_id,
                    'encrypted': encrypted,
                    'kms_key_id': kms_key_id,
                    'cluster_data': cluster
                })
                
                if encrypted and kms_key_id:
                    results.append(self.get_result(
                        'PASS', cluster_id,
                        f"DocumentDB 클러스터 {cluster_id}는 KMS로 암호화되어 있습니다.",
                        {
                            'cluster_id': cluster_id,
                            'encrypted': True,
                            'kms_key_id': kms_key_id
                        }
                    ))
                else:
                    results.append(self.get_result(
                        'FAIL', cluster_id,
                        f"DocumentDB 클러스터 {cluster_id}가 KMS로 암호화되어 있지 않습니다. | KMS 암호화를 활성화하세요.",
                        {
                            'cluster_id': cluster_id,
                            'encrypted': encrypted,
                            'kms_key_id': kms_key_id
                        }
                    ))
        
        except Exception as e:
            results.append(self.get_result('ERROR', 'N/A', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 60}
