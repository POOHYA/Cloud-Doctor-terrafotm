from .base_check import BaseCheck
from datetime import datetime
from typing import List, Dict

class IAMGluePassRoleCheck(BaseCheck):
    async def check(self) -> List[Dict]:
        iam = self.session.client('iam')
        results = []
        raw = []
        
        try:
            roles = iam.list_roles(MaxItems=1000)
            
            if not roles['Roles']:
                return {'results': results, 'raw': raw, 'guideline_id': 45}
            
            for role in roles['Roles']:
                role_name = role['RoleName']
                
                try:
                    attached_policies = iam.list_attached_role_policies(RoleName=role_name)
                    inline_policies = iam.list_role_policies(RoleName=role_name)
                    
                    has_glue_create = False
                    has_pass_role = False
                    
                    # 관리형 정책 확인
                    for policy in attached_policies['AttachedPolicies']:
                        try:
                            policy_version = iam.get_policy_version(
                                PolicyArn=policy['PolicyArn'],
                                VersionId=iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                            )
                            
                            for statement in policy_version['PolicyVersion']['Document'].get('Statement', []):
                                if statement.get('Effect') == 'Allow':
                                    actions = statement.get('Action', [])
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    
                                    for action in actions:
                                        if 'glue:CreateDevEndpoint' in action or action == '*':
                                            has_glue_create = True
                                        if 'iam:PassRole' in action or action == '*':
                                            has_pass_role = True
                        except Exception:
                            pass
                    
                    # 인라인 정책 확인
                    for policy_name in inline_policies['PolicyNames']:
                        try:
                            policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                            
                            for statement in policy_doc['PolicyDocument'].get('Statement', []):
                                if statement.get('Effect') == 'Allow':
                                    actions = statement.get('Action', [])
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    
                                    for action in actions:
                                        if 'glue:CreateDevEndpoint' in action or action == '*':
                                            has_glue_create = True
                                        if 'iam:PassRole' in action or action == '*':
                                            has_pass_role = True
                        except Exception:
                            pass
                    
                    raw.append({
                        'role_name': role_name,
                        'has_glue_create': has_glue_create,
                        'has_pass_role': has_pass_role
                    })
                    
                    if has_glue_create and has_pass_role:
                        results.append(self.get_result(
                            '취약', role_name,
                            f"역할 {role_name}에 glue:CreateDevEndpoint와 iam:PassRole 권한이 동시에 부여되어 있습니다.",
                            {
                                'role_name': role_name,
                                'has_glue_create': has_glue_create,
                                'has_pass_role': has_pass_role,
                                'attached_policies_count': len(attached_policies['AttachedPolicies']),
                                'inline_policies_count': len(inline_policies['PolicyNames'])
                            }
                        ))
                    else:
                        if has_glue_create or has_pass_role:
                            results.append(self.get_result(
                                '양호', role_name,
                                f"역할 {role_name}의 Glue/IAM 권한이 적절히 분리되어 있습니다.",
                                {
                                    'role_name': role_name,
                                    'has_glue_create': has_glue_create,
                                    'has_pass_role': has_pass_role,
                                    'attached_policies_count': len(attached_policies['AttachedPolicies']),
                                    'inline_policies_count': len(inline_policies['PolicyNames'])
                                }
                            ))
                        
                except Exception as e:
                    results.append(self.get_result('ERROR', role_name, f"역할 {role_name} 확인 중 오류: {str(e)}"))
                    
        except Exception as e:
            results.append(self.get_result('ERROR', 'N/A', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 45}