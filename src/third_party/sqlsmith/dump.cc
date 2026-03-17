#include <sstream>
#include <string>

#include "dump.hh"
#include "util.hh"

std::string graphml_dumper::id(struct prod *p) {
	std::ostringstream os;
	os << pretty_type(p) << "_" << p;
	return os.str();
}

graphml_dumper::graphml_dumper(std::ostream &out) : o(out) {
	o << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" << std::endl
	  << "<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\" "
	  << "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
	  << "xsi:schemaLocation=\"http://graphml.graphdrawing.org/xmlns "
	  << "http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd\">" << std::endl;

	o << "<key id=\"retries\" for=\"node\" "
	     "attr.name=\"retries\" attr.type=\"double\" />"
	  << std::endl;
	o << "<key id=\"label\" for=\"node\" "
	     "attr.name=\"label\" attr.type=\"string\" />"
	  << std::endl;
	o << "<key id=\"scope\" for=\"node\" "
	     "attr.name=\"scope\" attr.type=\"string\" />"
	  << std::endl;

	o << "<graph id=\"ast\" edgedefault=\"directed\">" << std::endl;
}

void graphml_dumper::visit(struct prod *p) {
	o << "<node id=\"" << id(p) << "\">";
	o << "<data key=\"retries\">" << p->retries << "</data>";
	o << "<data key=\"label\">" << pretty_type(p) << "</data>";
	o << "<data key=\"scope\">" << p->scope << "</data>";
	o << "</node>" << std::endl;
	if (p->pprod) {
		o << "<edge source=\"" << id(p) << "\" target=\"" << id(p->pprod) << "\"/>";
	}
	o << std::endl;
}

graphml_dumper::~graphml_dumper() {
	o << "</graph></graphml>" << std::endl;
}

void ast_logger::generated(prod &query) {
	std::string filename("");
	filename += "sqlsmith-";
	filename += std::to_string(queries);
	filename += ".xml";
	std::ofstream os(filename);
	graphml_dumper visitor(os);
	query.accept(&visitor);
	queries++;
}
