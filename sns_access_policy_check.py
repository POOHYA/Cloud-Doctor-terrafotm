from .base_check import BaseCheck
from datetime import datetime
from typing import List, Dict
import json

class SNSAccessPolicyCheck(BaseCheck):
    async def check(self) -> List[Dict]:
        sns = self.session.client('sns')
        results = []
        raw = []
        
        try:
            topics = sns.list_topics()
            
            if not topics['Topics']:
                results.append(self.get_result(
                    'PASS', 'N/A',
                    "SNS 주제가 존재하지 않습니다."
                ))
                return {'results': results, 'raw': raw, 'guideline_id': 1}
            
            for topic in topics['Topics']:
                topic_arn = topic['TopicArn']
                
                try:
                    attributes = sns.get_topic_attributes(TopicArn=topic_arn)
                    policy_str = attributes['Attributes'].get('Policy')
                    
                    if not policy_str:
                        results.append(self.get_result(
                            '양호', topic_arn,
                            f"주제 {topic_arn}에 액세스 정책이 설정되지 않았습니다.",
                            {'policy': None}
                        ))
                        continue
                    
                    policy = json.loads(policy_str)
                    raw.append({
                        'topic_arn': topic_arn,
                        'policy': policy
                    })
                    
                    vulnerable = False
                    issues = []
                    
                    for statement in policy.get('Statement', []):
                        principal = statement.get('Principal', {})
                        resource = statement.get('Resource', [])
                        action = statement.get('Action', [])
                        
                        # SNS 관련 액션 확인
                        sns_actions = []
                        if isinstance(action, str):
                            if 'sns:' in action.lower():
                                sns_actions.append(action)
                        elif isinstance(action, list):
                            sns_actions = [a for a in action if isinstance(a, str) and 'sns:' in a.lower()]
                        
                        if sns_actions:
                            # Principal 확인
                            if principal == "*" or (isinstance(principal, dict) and principal.get('AWS') == "*"):
                                vulnerable = True
                                issues.append(f"Principal이 '*'로 설정됨 (액션: {sns_actions})")
                            
                            # Resource 확인
                            if resource == "*" or (isinstance(resource, list) and "*" in resource):
                                vulnerable = True
                                issues.append(f"Resource가 '*'로 설정됨 (액션: {sns_actions})")
                    
                    if vulnerable:
                        results.append(self.get_result(
                            '취약', topic_arn,
                            f"주제 {topic_arn}의 액세스 정책에서 과도한 권한이 설정되어 있습니다: {', '.join(issues)}",
                            {
                                'policy': policy,
                                'issues': issues
                            }
                        ))
                    else:
                        results.append(self.get_result(
                            '양호', topic_arn,
                            f"주제 {topic_arn}의 액세스 정책이 적절히 제한되어 있습니다.",
                            {'policy': policy}
                        ))
                        
                except Exception as e:
                    results.append(self.get_result('ERROR', topic_arn, f"주제 {topic_arn} 정책 확인 중 오류: {str(e)}"))
                    
        except Exception as e:
            results.append(self.get_result('ERROR', 'N/A', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 1}