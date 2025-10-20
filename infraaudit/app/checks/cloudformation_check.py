from .base_check import BaseCheck
from datetime import datetime
from typing import List, Dict

class IAMRoleCloudFormationPassRoleCheck(BaseCheck):
    async def check(self) -> List[Dict]:
        iam = self.session.client('iam')
        results = []
        raw = []
        
        try:
            roles = iam.list_roles(MaxItems=1000)
            
            if not roles['Roles']:
                results.append(self.get_result(
                    '양호', 'N/A',
                    "IAM 역할이 존재하지 않습니다."
                ))
                return {'results': results, 'raw': raw, 'guideline_id': 41}
            
            for role in roles['Roles']:
                role_name = role['RoleName']
                
                try:
                    # 역할에 연결된 정책들 조회
                    attached_policies = iam.list_attached_role_policies(RoleName=role_name)
                    inline_policies = iam.list_role_policies(RoleName=role_name)
                    
                    has_create_stack = False
                    has_pass_role = False
                    vulnerable_policies = []
                    
                    # 관리형 정책 확인
                    for policy in attached_policies['AttachedPolicies']:
                        try:
                            policy_version = iam.get_policy_version(
                                PolicyArn=policy['PolicyArn'],
                                VersionId=iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                            )
                            
                            policy_doc = policy_version['PolicyVersion']['Document']
                            
                            for statement in policy_doc.get('Statement', []):
                                if statement.get('Effect') == 'Allow':
                                    actions = statement.get('Action', [])
                                    resources = statement.get('Resource', [])
                                    
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    if isinstance(resources, str):
                                        resources = [resources]
                                    
                                    # CloudFormation:CreateStack 권한 확인
                                    if any('cloudformation:CreateStack' in action.lower() or action == '*' for action in actions):
                                        if '*' in resources:
                                            has_create_stack = True
                                    
                                    # iam:PassRole 권한 확인
                                    if any('iam:PassRole' in action.lower() or action == '*' for action in actions):
                                        if '*' in resources:
                                            has_pass_role = True
                                    
                                    if has_create_stack and has_pass_role:
                                        vulnerable_policies.append(policy['PolicyName'])
                        except Exception:
                            pass
                    
                    # 인라인 정책 확인
                    for policy_name in inline_policies['PolicyNames']:
                        try:
                            policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                            
                            for statement in policy_doc['PolicyDocument'].get('Statement', []):
                                if statement.get('Effect') == 'Allow':
                                    actions = statement.get('Action', [])
                                    resources = statement.get('Resource', [])
                                    
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    if isinstance(resources, str):
                                        resources = [resources]
                                    
                                    # CloudFormation:CreateStack 권한 확인
                                    if any('cloudformation:CreateStack' in action.lower() or action == '*' for action in actions):
                                        if '*' in resources:
                                            has_create_stack = True
                                    
                                    # iam:PassRole 권한 확인
                                    if any('iam:PassRole' in action.lower() or action == '*' for action in actions):
                                        if '*' in resources:
                                            has_pass_role = True
                                    
                                    if has_create_stack and has_pass_role:
                                        vulnerable_policies.append(f"인라인 정책: {policy_name}")
                        except Exception:
                            pass
                    
                    raw.append({
                        'role_name': role_name,
                        'has_create_stack': has_create_stack,
                        'has_pass_role': has_pass_role,
                        'vulnerable_policies': vulnerable_policies
                    })
                    
                    if has_create_stack and has_pass_role:
                        results.append(self.get_result(
                            '취약', role_name,
                            f"역할 {role_name}에 CloudFormation:CreateStack과 iam:PassRole 권한이 모두 Resource '*'로 설정되어 있습니다.",
                            {
                                'role_name': role_name,
                                'has_create_stack': has_create_stack,
                                'has_pass_role': has_pass_role,
                                'vulnerable_policies': vulnerable_policies
                            }
                        ))
                    else:
                        # 두 권한 중 하나라도 있는 경우만 양호로 표시
                        if has_create_stack or has_pass_role:
                            results.append(self.get_result(
                                '양호', role_name,
                                f"역할 {role_name}의 CloudFormation/IAM 권한이 적절히 제한되어 있습니다.",
                                {
                                    'role_name': role_name,
                                    'has_create_stack': has_create_stack,
                                    'has_pass_role': has_pass_role
                                }
                            ))
                        
                except Exception as e:
                    results.append(self.get_result('ERROR', role_name, f"역할 {role_name} 확인 중 오류: {str(e)}"))
                    
        except Exception as e:
            results.append(self.get_result('ERROR', 'N/A', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 41}