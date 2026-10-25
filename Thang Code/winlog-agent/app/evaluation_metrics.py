"""Explicit denominators; repeats never become independent cases."""
from collections import defaultdict
from statistics import median


def ratio(n,d): return {'numerator':n,'denominator':d,'value':n/d if d else None}


def aggregate(results):
    labels=[r.get('label') if not r.get('technical_error') else 'UNKNOWN' for r in results]
    if 'ALERT' in labels: return 'ALERT'
    if not labels or any(label!='NORMAL' for label in labels): return 'UNKNOWN'
    return 'NORMAL'


def sum_measure(results,key):
    values=[r.get(key) for r in results]
    return sum(values) if values and all(v is not None for v in values) else None


def metrics(rows):
    tp=sum(r['ground_truth']=='ALERT' and r['label']=='ALERT' for r in rows)
    fp=sum(r['ground_truth']=='NORMAL' and r['label']=='ALERT' for r in rows)
    fn=sum(r['ground_truth']=='ALERT' and r['label']!='ALERT' for r in rows)
    tn=sum(r['ground_truth']=='NORMAL' and r['label']=='NORMAL' for r in rows)
    unknown=sum(r['label']=='UNKNOWN' for r in rows)
    attempts=sum(len(r['attempts']) for r in rows)
    responses=sum(a.get('response') is not None for r in rows for a in r['attempts'])
    valid=sum(a.get('response') is not None and not a.get('technical_error') for r in rows for a in r['attempts'])
    reviews=[r['review'] for r in rows if r.get('review') is not None]
    return {'cases':len(rows),'tp':tp,'fp':fp,'fn':fn,'tn':tn,'unknown':unknown,
            'technical_error_cases':sum(any(a.get('technical_error') for a in r['attempts']) for r in rows),
            'precision':ratio(tp,tp+fp),'recall':ratio(tp,tp+fn),'f1':ratio(2*tp,2*tp+fp+fn),
            'coverage':ratio(len(rows)-unknown,len(rows)),'false_positive_rate':ratio(fp,fp+tn+sum(r['ground_truth']=='NORMAL' and r['label']=='UNKNOWN' for r in rows)),
            'json_valid_response':ratio(valid,responses),'response_attempt':ratio(responses,attempts),
            'account_session_error':ratio(sum(r['incorrect'] for r in reviews),len(reviews))}


def comparison(rows):
    grouped=defaultdict(list)
    for row in rows: grouped[(row['model'],row['mode'],row['repeat'])].append(row)
    return [{'model':m,'mode':mode,'repeat':repeat,'primary':repeat==1,**metrics(items)}
            for (m,mode,repeat),items in sorted(grouped.items())]


def timings(rows):
    groups=defaultdict(list)
    for row in rows: groups[(row['model'],row['mode'],row['case_id'])].append(row)
    output=[]
    for (model,mode,case),items in groups.items():
        successful=[r for r in items if r['attempts'] and all(not a.get('technical_error') for a in r['attempts']) and r['wall_seconds'] is not None]
        complete=len(successful)==3 and {r['repeat'] for r in successful}=={1,2,3}
        output.append({'model':model,'mode':mode,'case_id':case,'successful_repeats':len(successful),
                       'median_wall_seconds':median(r['wall_seconds'] for r in successful) if complete else None,
                       'complete_three_repeats':complete})
    return output
